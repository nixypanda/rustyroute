# RustyRoute

traceroute and tracert are computer network diagnostic commands for displaying
possible routes (paths) and measuring transit delays of packets across an
Internet Protocol (IP) network. The history of the route is recorded as the
round-trip times of the packets received from each successive host (remote
node) in the route (path); the sum of the mean times in each hop is a measure
of the total time spent to establish the connection. This a toy-clone of that
application.


## Requirements
- Understanding of [IP](https://datatracker.ietf.org/doc/html/rfc791)
- Understanding of [ICMP](https://datatracker.ietf.org/doc/html/rfc792)

## Theory

Let's start by diving into some netorking theory.

IP header has a field ttl (Time to live). It helps to prevent a packet from
looping forever. How?

From the RFC -
>    Time to Live
>      Time to live in seconds; as this field is decremented at each
>      machine in which the datagram is processed, the value in this
>      field should be at least as great as the number of gateways which
>      this datagram will traverse.

The key point to note is that this field is decremented at each machine in
which the datagram is processed. i.e. every router, etc along the path will
decrement this field by 1.

### What happens to a packet whose ttl reaches 0?

When a Router sees a packet whose ttl is expired (i.e. the ttl count has
reached 0)
- the router discards the packet
- sends back an ICMP message with `TTL_EXPIRED` back to the host
  - Note: we can extract the details of the router that rejects the packet from
    TTL_EXPIRED message that we receive

This gives us the necessary insight required to make something like traceroute.
What if we start with a ttl value of 1 and increase it till we reach a stopping
condition (discussed in the next section). Each packet will be rejected by the
next router in path (compared to the previous one). Thus helping us trace the
whole path.

### How to stop?

There are various ways one can decide to stop this process.

#### Check source address of ICMP response is same as destionation

We check if the source address of the ICMP response that we receive is same as
the destination that we want to reach. If that is indeed the case then we can
stop.

#### Using UDP packets

This approach relies what happens when you send a UDP packet to an incorrect
port number. When this case arises, the destination host -
- discards the packet
- sends back a `PORT_UNREACHABLE` ICMP packet


## High level flow
1. Sets the value of the TTL=1
2. Create an IP packet with the ttl value
    - dosen't matter what the contents of this packet are
3. Start a timer
4. Send the packet out
    - The first router sees this packet decrements the TTL field sees that it
      is zero, consequently discards the packet and sends the `TTL_EXPIRED`
      message with it's address in the `SOURCE_ADDRESS` field. 
4. Upon receiving the packet validates it
5. Read the `SOURCE_ADDRESS`
6. stop the timer
7. Calculate the elpased time
8. Disply this info to the user
9. Increment the TTL
10. Repeat steps 2 to 9 again and again untile stopping condition is triggered


## Execution

`./run.sh --url=<ipv4 address of the destination>`

Note: In order to keep the code simple
- we don't do dns resolution so it expects an ipv4 address and not a url
- no reverse dns resolution is done for the ip addresses that we recevieve from
  each hop
- only one packet is sent out and not 3 like the original traceroute does

