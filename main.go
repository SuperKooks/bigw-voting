package main

import (
	"bigw-voting/bgw"
	"bigw-voting/commands"
	"bigw-voting/p2p"
	"bigw-voting/shamir"
	"bigw-voting/ui"
	"bigw-voting/util"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"time"

	upnp "github.com/huin/goupnp/dcps/internetgateway2"
)

var votepack *Votepack
var localVotes map[string]int

var allVoters []*Voter
var localStatus string

var externalIP string

func main() {
	util.StartLogging()
	parseCommandline()
	votepack = NewVotepackFromFile(flagVotepackFilename)
	if flagTrusteeExport {
		ExportTrusteeVote()
	}

	commands.VotepackTrustees = votepack.TrusteeVotes
	commands.RegisterAll()

	go ui.Start()
	defer ui.Stop()

	time.Sleep(100 * time.Millisecond)
	ui.NewVote(votepack.Candidates, SubmitVotes)

	// Find local IP for BGW as well as for UPNP mapping
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	var localIP string
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			panic(err)
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if !util.IsPublicIP(v.IP.String()) && v.IP.To4() != nil {
					localIP = v.IP.String()
					break
				}
			case *net.IPAddr:
				if !util.IsPublicIP(v.IP.String()) && v.IP.To4() != nil {
					localIP = v.IP.String()
					break
				}
			}
		}
	}

	if !flagNoUPNP {
		clients, _, err := upnp.NewWANIPConnection1Clients()
		if err != nil {
			panic(err)
		}

		if len(clients) > 1 {
			ui.Stop()
			panic("detected multiple gateway devices")
		}

		if len(clients) < 1 {
			util.Warnln("Did not detect any gateway devices, if you are behind a NAT, you cannot act as an intermediate")
		}

		if len(clients) == 1 {
			client := clients[0]

			util.Infof("Using local IP %v for port mapping\n", localIP)

			// Check for an entry before creating one
			intPort, _, _, _, _, err := client.GetSpecificPortMappingEntry("", 42069, "udp")
			if intPort != 42069 {
				util.Infoln("Creating new port mapping")

				// Create a new port mapping allowing all remotes to connect to us on port 42069 for 30 minutes
				err = client.AddPortMapping("", 42069, "udp", 42069, localIP, true, "BIGW Voting", 1800)
				if err != nil {
					panic(err)
				}
			}

			util.Infoln("Port mapping is established")

			// Get external IP
			externalIP, err = client.GetExternalIPAddress()
			if err != nil {
				panic(err)
			}
			util.Infof("Starting intermediate server at external IP: %v:42069\n", externalIP)
		}
	}

	// Find our public IP
	if !util.IsPublicIP(externalIP) {
		var extIP string
		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err != nil {
				panic(err)
			}

			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if util.IsPublicIP(v.IP.String()) {
						extIP = v.IP.String()
						break
					}

				case *net.IPAddr:
					if util.IsPublicIP(v.IP.String()) {
						extIP = v.IP.String()
						break
					}
				}
			}
		}

		externalIP = extIP
	}

	localStatus = "Voting InProgress"

	p2p.Setup(externalIP, NewPeerCallback)

	_, err = p2p.StartConnection(fmt.Sprintf("%v:%v", flagIntermediateIP, flagIntermediatePort), flagPeerIP)
	if err != nil {
		ui.Stop()
		panic(err)
	}

	// Wait for Ctrl-C
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
}

// NewPeerCallback serves as the callback for when new peers are connected.
// It verifies the votepack is consistent and syncs trustee votes.
func NewPeerCallback(p *p2p.Peer) {
	// Create voter structure
	voter := NewVoter(p)
	allVoters = append(allVoters, voter)

	// Start a goroutine (one per peer) for a listener
	go listener(voter)

	// Verify votepack with new peer
	util.Infoln("Verifying votepack with new peer")
	hash := sha256.Sum256(votepack.Export())
	err := p.SendMessage(append([]byte("VotepackVerify "), hash[:]...))
	if err != nil {
		util.Errorf("Unable to send message to %v, %v\n", p.PeerAddress.IP.String(), err)
	}

	ui.AddPeerToList(p.PeerAddress.IP.String(), "Votepack Verified")

	// Send our current status to the peer
	err = p.SendMessage([]byte("StatusUpdate " + localStatus))
	if err != nil {
		util.Errorf("Unable to send message to %v, %v\n", p.PeerAddress.IP.String(), err)
	}

	// Update the peer with our trustee votes
	for _, v := range commands.LocalTrusteeVotes {
		err = p2p.BroadcastMessage([]byte("TrusteeVote "+v.Name), 0)
		if err != nil {
			util.Errorln(err)
			return
		}
	}
}

// SubmitVotes is the callback for the instantFunoff voting submit button
func SubmitVotes(submittedVotes map[string]int) {
	localStatus = "Voting Complete"
	localVotes = submittedVotes

	// UpdateStatus to all peers
	err := p2p.BroadcastMessage([]byte("StatusUpdate "+localStatus), 0)
	if err != nil {
		util.Errorf("Unable to broadcast status update: %v\n", err)
	}

	for _, v := range allVoters {
		if v.Status != "Voting Complete" {
			// Don't begin BGW if peers have not finished voting
			return
		}
	}

	// Proceed with BGW
	go RunBGW()
}

// RunBGW begins the BGW protocol, with circuits for each round of voting
func RunBGW() {
	// A IRV is used to eliminate candidates until there are only 3 left
	// https://en.wikipedia.org/wiki/Instant-runoff_voting

	// For each round of IRV, the number of votes must be tallied for each candidate.
	// This means there must be a BGW circuit for each candidate for each round.
	// In a 5 candidate election, that means there must be 5+4 = 9 circuits.

	// Create deep copy of elements, so we don't mess up the original candidates
	currentCandidates := make([]string, len(votepack.Candidates))
	copy(currentCandidates, votepack.Candidates)

	sortedPeerIPs := p2p.GetAllPeerIPs()
	sort.Strings(sortedPeerIPs)

	allPeerIPs := append(sortedPeerIPs, externalIP)
	sort.Strings(allPeerIPs)

	for len(currentCandidates) > 3 {
		// Add votes for each candidate (in alphabetical order)
		currentVotes := make(map[string]int)
		sort.Strings(currentCandidates)
		irvVote := getIRVVote(currentCandidates, localVotes)

		// Pre-calculate trustee votes
		trusteeVotes := make(map[string]int)
		for _, v := range commands.LocalTrusteeVotes {
			trusteeIRV := getIRVVote(currentCandidates, v.Votes)
			trusteeVotes[trusteeIRV]++
		}

		for _, v := range currentCandidates {
			// Synchronise peers using status
			localStatus = "Tallying " + v
			err := p2p.BroadcastMessage([]byte("StatusUpdate "+localStatus), 0)
			if err != nil {
				util.Errorf("Unable to broadcast status update: %v\n", err)
			}

			for {
				var desynchronised bool
				for _, v := range allVoters {
					if v.Status != localStatus {
						desynchronised = true
						break
					}
				}

				if !desynchronised {
					break
				}
			}

			// Should we vote for this candidate?
			shouldVote := 0
			util.Infoln("Running tally for", v)
			util.Infoln("IRV", irvVote)
			if v == irvVote {
				util.Infoln("Voting for candidate", v)
				shouldVote = 1
			}

			// Create BGW circuit
			head, shares := bgw.NewVotingCircuit(shouldVote+trusteeVotes[v], externalIP, sortedPeerIPs)

			// Send shares to peers
			for k, v := range shares {
				for _, voter := range allVoters {
					if voter.Peer.PeerAddress.IP.String() == k {
						// Marshal shares
						b, err := json.Marshal(v)
						if err != nil {
							util.Errorln("Unable to marshal peer shares")
						}

						util.Infoln("Sending:", string(append([]byte("YourShares "), b...)))
						err = voter.Peer.SendMessage(append([]byte("YourShares "), b...))
						if err != nil {
							util.Errorf("Unable to broadcast peer share: %v\n", err)
						}
					}
				}
			}

			// Wait for all peer shares to be received
			for {
				if len(receivedPeerShares) == len(sortedPeerIPs) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			// Sort peer shares then descend circuit
			var sortedPeerShares []int
			for _, v := range sortedPeerIPs {
				sortedPeerShares = append(sortedPeerShares, receivedPeerShares[v]...)
			}
			util.Infoln("Descending circuit with", sortedPeerShares)
			bgw.DescendCircuit(head, sortedPeerShares)

			// Get output of circuit and broadcast
			circuitOut := head.GetOutput()
			util.Infoln("Broadcasting", fmt.Sprintf("MyOutput %v", circuitOut))
			err = p2p.BroadcastMessage([]byte(fmt.Sprintf("MyOutput %v", circuitOut)), 0)
			if err != nil {
				util.Errorf("Unable to broadcast circuit output: %v\n", err)
			}

			receivedPeerOutputs[externalIP] = circuitOut

			// Wait for all peer outputs to be recieved
			for {
				// Note: allPeerIPs not sortedPeerIPs as we add our result in
				if len(receivedPeerOutputs) == len(allPeerIPs) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}

			util.Infoln("Local circuit output is", receivedPeerOutputs[externalIP])

			// Sort peer outputs then add votes
			var sortedPeerOutputs [][2]int
			for k, v := range allPeerIPs {
				util.Infof("x: %v, peer: %v, peer-out: %v\n", k+1, v, receivedPeerOutputs[v])
				sortedPeerOutputs = append(sortedPeerOutputs, [2]int{k + 1, receivedPeerOutputs[v]})
			}

			util.Infoln("Reconstructing with", sortedPeerOutputs)
			currentVotes[v], err = shamir.ReconstructSecret(sortedPeerOutputs)
			if err != nil {
				util.Errorln("Could not reconstruct circuit output: ", err)
			}

			util.Infoln("Reconstructed", currentVotes[v])

			// Clear all received maps to prevent bad results
			receivedPeerOutputs = make(map[string]int)
			receivedPeerShares = make(map[string][]int)
		}

		util.Infoln(currentVotes)

		// Ensure that the number of votes does not exceed the number of peers + trustees + us
		var numOfVotes int
		for _, v := range currentVotes {
			numOfVotes += v
		}

		if numOfVotes > len(p2p.GetAllPeerIPs())+len(commands.AllTrusteeVotes)+1 {
			util.Errorln("A peer has voted twice! Number of votes exceeds the number of peer + trustees")
			return
		}

		// Eliminate worst candidate
		var worstCandidate string
		worstCandidateVotes := -1
		for k, v := range currentVotes {
			if v < worstCandidateVotes || worstCandidateVotes == -1 {
				worstCandidate = k
				worstCandidateVotes = currentVotes[k]
			}
		}

		util.Infoln("Eliminating candidate", worstCandidate)

		for k, v := range currentCandidates {
			if v == worstCandidate {
				currentCandidates = append(currentCandidates[:k], currentCandidates[k+1:]...)
			}
		}
	}

	util.Infoln("ELECTED CANDIDATES:")
	util.Infoln(currentCandidates)
}

// getIRVVote gets the best vote for a given set of candidates
func getIRVVote(currentCandidates []string, votes map[string]int) string {
	orderedVotes := make([]string, len(votes))
	for k, v := range votes {
		orderedVotes[v-1] = k
	}

	// Find best vote for current candidates
	var selected string
	for _, v := range orderedVotes {
		// Check that candidate voted for is a current candidate
		for _, w := range currentCandidates {
			if w == v {
				selected = v
				break
			}
		}

		// If we have found the candidate then we are all good
		if selected != "" {
			break
		}
	}

	return selected
}
