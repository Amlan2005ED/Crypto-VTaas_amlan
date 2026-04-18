# Cryptography VTaaS

## Overview
Cryptography VTaaS is a zero-knowledge verification demo that shows how cryptographic proofs can support trustworthy clinical data analysis. The project is built around the idea of verifying a medical-trial outcome without revealing every underlying record. Instead of asking users to trust a reported result, the system generates a proof that confirms the computation was performed correctly. This makes the project a useful example of how privacy-preserving verification can be applied to healthcare, research, and other sensitive-data environments where integrity matters as much as confidentiality.

## Project Goal
The main goal of this project is to demonstrate Verifiable Trust as a Service through a simple but meaningful use case. Patient data is submitted to the backend, a recovery-rate calculation is executed inside the RISC Zero zkVM, and the final result is returned along with proof-related artifacts. In this flow, the verifier can trust the reported success rate without needing direct access to the raw dataset. That makes the system relevant for domains where auditability, privacy, and tamper-resistance are critical.

## Tech Stack
- Rust workspace architecture
- Axum for the backend API
- Tokio for async runtime support
- RISC Zero zkVM for zero-knowledge proof generation
- Serde and Serde JSON for data serialization
- Static HTML frontend for presenting the interface

## How It Works
The project is divided into two main parts: the host application and the methods guest code. The host exposes an HTTP endpoint at /prove and receives a list of patient records. Each record contains a patient ID, a flag indicating whether the patient received the drug, and a flag showing whether recovery occurred.

The guest method processes that data inside the zkVM. It counts how many patients received the drug, counts how many of those patients recovered, and calculates the percentage success rate. That computed rate is committed to the proof journal. The host then returns a JSON response containing the verification status, the success rate, the method ID, and a serialized proof receipt.

## Running the Project
Make sure Rust is installed, then run:

bash
cargo run -p host


This starts the API locally at http://127.0.0.1:3000.

## Why It Matters
This project highlights how zero-knowledge systems can improve trust in sensitive workflows. Rather than exposing private medical records, it proves that the result was produced correctly. That makes Cryptography VTaaS a strong educational prototype for privacy-preserving analytics, compliance-oriented systems, and secure data verification.
