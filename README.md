# Instant Akismet: Akismet spam detection client written in Rust

[![Documentation](https://docs.rs/instant-akismet/badge.svg)](https://docs.rs/instant-akismet/)
[![Crates.io](https://img.shields.io/crates/v/instant-akismet.svg)](https://crates.io/crates/instant-akismet)
[![Build status](https://github.com/InstantDomain/instant-akismet/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/InstantDomain/instant-akismet/actions/workflows/rust-ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Instant Akismet is a full set of Rust bindings for the [Akismet](https://akismet.com/) spam-detection service and is used in production over at [Instant Domains](https://instantdomains.com) to help us protect our users' sites from comment and messaging spam.

## Features

- Supports all Akismet API features
  - Akismet key verification
  - Comment spam check
  - Report spam (false negative)
  - Report ham (false positive)
- Akismet pro-tip handling 
- Full Akismet error propagation
- Unit tests for all API features
  
## Getting Started

To begin with, you'll need to head over to [Akismet](https://akismet.com/development/) and join the developer program to obtain an API key. 
> Note: In order to run the included tests, this key should be set as AKISMET_KEY in your environment.

## Usage

```rust
// Initialize client
let akismet_client = AkismetClient::new(
    String::from("https://exampleblog.com"), // The URL for your blog
    akismet_key, // Your Akismet API key
    reqwest::Client::new(), // Reqwest client to use for requests
    AkismetOptions::default(), // AkismetOptions config
);

// Verify key
akismet_client.verify_key().await?;

// Create a comment
let comment = Comment::new(akismet_client.blog.as_ref(), "8.8.8.8")
    .comment_author("exampleUser1")
    .comment_author_email("example-user@example.com")
    .comment_content("example comment content");

// Check comment for spam
let is_spam = akismet_client.check_comment(comment).await?;
```

## Testing

In order to run the included tests, you will need to ensure that you have your API key set as AKISMET_KEY in your environment.
```
cargo test
```