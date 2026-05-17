# OverTheWire Bandit: Level 0 → Level 1
**Date:** 2026-05-17
**Category:** Linux Fundamentals / SSH
**Difficulty:** Beginner

---

## Overview

Bandit is OverTheWire's beginner wargame designed to teach the Linux command 
line through progressively harder challenges. Each level gives you credentials 
and a task to find the next password. This is Level 0 → 1: connecting to the 
game server via SSH and reading a file from the home directory.

**Goal:** SSH into the Bandit server as `bandit0` and find the password for `bandit1`.

---

## Enumeration

Once connected, the first step is understanding what's in the environment.

```bash
$ ssh bandit0@bandit.labs.overthewire.org -p 2220
bandit0@bandit.labs.overthewire.org's password: bandit0

bandit0@bandit:~$ ls -la
total 24
drwxr-xr-x  2 root    root    4096 Sep 19 07:08 .
drwxr-xr-x 70 root    root    4096 Sep 19 07:08 ..
-rw-r-----  1 bandit1 bandit0   33 Sep 19 07:08 readme
```

The `readme` file is owned by `bandit1` but readable by `bandit0`.
No hidden tricks yet — the answer is right there.

---

## Exploitation

```bash
bandit0@bandit:~$ cat readme
NH2SXQwcBdpmTEzi3bvBHMM9H1Zs
```

That's the password for `bandit1`.

---

## The Vulnerability

No real vulnerability here — this level introduces **file permissions and 
ownership**. The file is readable by members of the `bandit0` group. In a 
real environment, leaving sensitive files world-readable or group-readable 
is a genuine misconfiguration: **CWE-732: Incorrect Permission Assignment 
for Critical Resource**.

---

## How to Fix It

In a real system, a credentials file like this should:

1. Be readable only by its owner:
```bash
$ chmod 600 readme
```
2. Live in a directory with restricted access:
```bash
$ chmod 700 /home/bandit0
```
3. Not contain plaintext credentials at all — use a secrets manager
   (AWS Secrets Manager, HashiCorp Vault, etc.)

---

## What I Learned

- SSH non-standard port syntax:
```bash
$ ssh user@host -p PORT
```
- `ls -la` reveals permissions, ownership, and hidden files simultaneously
- File permission triplets (`rw-r-----`) map to owner / group / world
- Real-world parallel: misconfigured file permissions are one of the most 
  common findings in cloud security audits — exposed `.env` files, public 
  S3 buckets, world-readable config files

**Next:** Level 1 → 2 — reading a file named `-`

---

*Lawrence | cybersecurity-portfolio/writeups/bandit-level-0-1.md*
