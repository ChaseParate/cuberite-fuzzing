#let title = "Final Project Report"
#let authors = ("Chase Harkcom", "Max Petersen")
#let authors_text = authors.join(" and ")

#set document(author: authors, title: title)
#set page(
  paper: "a4",
  margin: 0.75in,
  footer: context [
    #authors_text
    #h(1fr)
    #counter(page).display()
  ],
)
#set par(
  justify: true,
  spacing: 1em,
  // first-line-indent: (
  //   amount: 3em,
  //   all: true,
  // ),
)
#set text(size: 12pt)

#show link: underline
#show link: text.with(fill: blue)

= #title - #authors_text

== Background
// What is Cuberite and the MC protocol.
We decided to fuzz #link("https://cuberite.org/")[Cuberite], which is a third-party implementation of a multiplayer Minecraft server written in C++.
Initially, we wanted to target Cuberite specifically because of the language it was written in, as we had experience harnessing C++ code from the class's labs.
However, as we discussed more about our goals and possible avenues for approaching our project, we ended up pivoting to network fuzzing instead of direct coverage-guided fuzzing.
We chose this primarily because of the access that a typical attacker would have to such a server: just sending packets via the network
An attacker may be able to send some maliciously crafted packet to a server, allowing illegal access to private resources (e.g., privilege escalation) or simply crash the server (causing a denial of service).
The Minecraft protocol, which Cuberite follows, consists of various clientbound (server to client) and serverbound (client to server) packets.
Sending packets allows clients to connect and authenticate, perform actions, and otherwise communicate with the server, whereas the client receives packets from the server to be able to render the state of the virtual world, other players, and more.

== Approach
// How we approached fuzzing this---network stack.
As mentioned before, we targeted the network stack of Cuberite to try and find some "packet of doom" that would cause a denial of service or otherwise find some vulnerability.

We used #link("https://boofuzz.readthedocs.io/en/stable/")[`boofuzz`] (a state-of-the-art network protocol fuzzer) to accomplish this, which was recommended by Professor Nagy.
`boofuzz` is a black-box, model-guided fuzzer, meaning we do not need to instrument the Cuberite executable with AFL bindings or anything like that.
However, we did compile Cuberite with ASan and UBSan to hopefully find some crash originating from there, but as of writing, all we've yielded from this are annoying signed overflow warnings from UBSan.
#footnote[
  *Sidenote*: Because we targeted specifically the network stack, our fuzzer is actually able to fuzz the network stack of _any_ Minecraft server given they follow the Minecraft protocol, including the official Java implementation from Mojang.
  We attempted to do so, but encountered some protocol errors close to the project deadline, so we are leaving this to future work.
]

In order to use `boofuzz`, we needed to define the models for each packet/request.
The Minecraft protocol involves many interesting/proprietary encodings and data models that `boofuzz` understandably did not provide out of the box; some examples include variable length integers and a compressed 3D vector.
Max was the primary developer for writing not only the raw encoding/decoding logic for these, but also the custom "block" types for use in `boofuzz`.

Cuberite supports up to version 1.12.2 of the game (released September 2017) #footnote[Frankly, "support" is a bit of a stretch.
Many features are incomplete or inaccurate to the official Minecraft server, but this version seemed to be the most stable from our preliminary testing.], so we had to #link("https://c4k3.github.io/wiki.vg/Protocol.html")[find an archive of some community-driven documentation for the protocol for that older version of the game], which still had some inaccuracies, so we also used #link("https://github.com/prismarinejs/minecraft-data")[this other large data collection] to verify our packets were accurate.
The Minecraft protocol is a stateful protocol, meaning we had to retain some information from earlier received packets (thus, we actually needed to unmarshall these clientbound packets) and use that data to hotswap values in later-sent packets.
For example, during the login sequence of the protocol, the server sends the client a packet saying "you should spawn your player at this position", and the client must respond with a packet saying "I have spawned at that exact location", otherwise they will be kicked from the server.
We had to do a lot of finagling to get this to work, as `boofuzz` does not currently support this, to our knowledge.
We implemented hot-swapping the "default" value of a block using a callback after every fuzzer sub-step in the packet sequence.
In total, we implemented 11 serverbound packets (the actual data being mutated and sent by the fuzzer) and 9 clientbound packets (which are used for the stateful steps of the protocol and triage/debugging).
These packets include the entirety of the login sequence (meaning players are successfully able to join and be seen in game) alongside a few other gameplay-specific packets, like breaking a block and using an item.
Chase was the primary developer for these packets, with Max chipping in for some of them as well.

All of our fuzzing code can be found #link("https://github.com/ChaseParate/cuberite-fuzzing")[in this GitHub repo].

== Results
// Bugs we found, etc.
We ended up finding 2 bugs in Cuberite's network stack, both of which are reported on GitHub.

https://github.com/cuberite/cuberite/issues/5639

https://github.com/cuberite/cuberite/issues/5640

Issue \#5639 was found by our fuzzer only because of the way it operates. since it generates a bunch of random players to join and leave the server, it's able to trigger some kind of race condition that stops the player count from decrementing correctly when a player leaves the server after a certain number of joins/leaves in quick succession. This was actually a challenge during fuzzing because we had to make the max player count super high on the server to allow players to join/leave many times without getting a "server is full" error.

Issue \#5640 was actually the "packet of doom" we were looking for, because it really can be triggered with just one packet. We found that a certain type of packet called a "Plugin Message", used to transmit arbitrary data over a channel with a given name, could crash the server by triggering an assertion error when the channel's name is very long. Our "packet of doom" in this case is just a compressed packet containing a 40,000 character channel name, which we assume triggers buffer overflow prevention code that aborts the server when it tries to send back an "UNREGISTER" channel message with the channel name to report the channel name as unrecognized.

== Conclusion
// Reflection, how we could improve/extend the project, etc.
Using this black-box fuzzing strategy, we were able to find a couple interesting bugs, which shows that testing the network stack of a game server like this is a viable strategy. It might even have some reproducibility benefits over a traditional AFL harness, because it doesn't require any changes to the code and works across different languages/architectures.

In the future, it could be interesting to try and extend this type of fuzzer to work across all server implementations, but as of right now it would probably require some changes to Boofuzz's internals to make our clientbound packet handling more robust in the event of the server forcefully closing the connection (which the Java server is a lot more aggressive about).

Since our grammar-guided fuzzing technique uses a sort of state machine anyways to track which packets to send / the validity of certain packets, it could also be interesting to extend this state machine to have even more validation on the client state returned by the server. This might slow down our fuzzing even more from the usual 10-30 executions/sec, but it could be used to catch bugs that don't crash the server but do enable cheating.
