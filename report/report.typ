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
MAX TODO

== Conclusion
// Reflection, how we could improve/extend the project, etc.
MAX TODO
