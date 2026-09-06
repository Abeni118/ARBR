# Attack-Resistant Backup and Recovery System

A cybersecurity system that protects an organization’s critical data from ransomware and other cyber threats by monitoring files and backups, detecting and analyzing suspicious activity, protecting and isolating data, and providing recovery options from verified, safe backups.

## The Problem

Cybersecurity threats such as ransomware can target enterprise files and encryption keys, rendering data inaccessible through encryption or deletion. In addition, ransomware may target and destroy backup files, rendering data recovery unrecoverable.

Enterprises need an attack-resistant cybersecurity system that detects and analyzes ransomware and other malicious activity, protects backup data, isolates affected systems, and restores files from protected, verified backups.

## Project Goal
The goal of this project is to design a system that
1. Detects ransomware and other file-encrypting malware through behavioral analysis of file access and modification patterns,
2. Protects enterprise files and backups through isolation and tamper-protection mechanisms,

3. Analyzes and prioritizes security threats based on risk values,
4. Verifies the integrity of backup data to be used for enterprise file recovery,
5. Recovers files from safely isolated, unaltered data backups in response to detected ransomware attacks, and
6. Records relevant events for auditing and forensics.
The proposed solution addresses ransomware and cybersecurity threats by monitoring, detecting, analyzing, protecting, isolating, verifying, and recovering data according to the automated procedure in Figure 1 below:
```
Figure 1: Cybersecurity and Data Recovery Procedure

Monitor
↓
Detect
↓
Analyze Risk
↓
Protect Backup
↓
Isolate
↓
Verify Backup
↓
Recover
↓
Report
```
