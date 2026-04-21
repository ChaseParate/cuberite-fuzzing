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
CHASE TODO

== Approach
// How we approached fuzzing this---network stack.
CHASE TODO

== Results
// Bugs we found, etc.
We ended up finding 2 bugs in Cuberite's network stack, both of which are reported on GitHub.

https://github.com/cuberite/cuberite/issues/5639

https://github.com/cuberite/cuberite/issues/5640

Issue \#5639 was found by our fuzzer only because of the way it operates. since it generates a bunch of random players to join and leave the server, it's able to trigger some kind of race condition that stops the player count from decrementing correctly when a player leaves the server after a certain number of joins/leaves in quick succession. This was actually a challenge during fuzzing because we had to make the max player count super high on the server to allow players to join/leave many times without getting a "server is full" error.

Issue \#5640 was actually the "packet of doom" we were looking for, because it really can be triggered with just one packet. We found that a certain type of packet called a "Plugin Message", used to transmit arbitrary data over a channel with a given name, could crash the server by triggering an assertion error when the channel's name is very long. Our "packet of doom" in this case is just a compressed packet containing a 40,000 character channel name, which we assume triggers buffer overflow prevention code that aborts the server when it tries to send back an "UNREGISTER" channel message with the channel name to report the channel name as unrecognized.

== Conclusion
// Reflection, how we could improve/extend the project, etc.
MAX TODO
