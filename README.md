[![Build Status](https://travis-ci.com/sid-project/sid.svg?branch=master)](https://travis-ci.com/sid-project/sid)


# Storage Instantiation Daemon

Storage Instantiation Daemon (SID) is a project that aims to help with
Linux storage device state tracking that encompasses device layers,
groups and whole stacks by monitoring progression of events. Based on
monitored states and further recorded information, it is able to trigger
associated actions for well-defined triggers, including activation and
deactivation of devices and their layers in the stack.

SID positions itself on top of *udev*, reacting to *uevents*. It is
closely interlinked and cooperating with *udev daemon*. The udev daemon
is enhanced with specialized *sid* udev builtin command that is used to
communicate with SID. SID also listens to *udev uevents* issued by udev
daemon which in turn triggers further processing.

At its core, SID provides an *infrastructure* and an *API* for various
device subsystems to create *modules* that handle specific device types
and their abstractions. For this purpose, it organizes overall uevent
processing into *discrete and controlled steps* and, through an API, it
provides access to its own *SID database* for use within core parts as
well as modules to store and retrieve extended information besides udev
daemon’s database capabilities.

The SID database contains both *internal* and *general-purpose records*.
The internal records are accessed only through dedicated API calls which
are used to track and support device dependencies, grouping, triggers
and associated actions. The general-purpose records can be stored and
retrieved by modules directly with a possibility to define their *key
components*, *scope of visibility* and *access type*.

Since SID keeps track of the overall storage device stack and grouping,
it provides an insight into the stack, the device and group dependencies
and it is able to notify when there are changes to certain parts of the
device stack to which there needs to be an appropriate action executed
either inside (using SID’s triggers and associated actions) or outside
SID itself (using *extended notifications* that SID sends out).
