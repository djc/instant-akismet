//! Akismet spam detection client.

#![warn(unreachable_pub)]
#![warn(missing_docs)]

use std::borrow::Cow;

use chrono::{serde::ts_seconds_option, DateTime, Utc};
use reqwest::Client;
use serde::Serialize;
use thiserror::Error;

/// A client for the Akismet spam detection service
///
/// Create an [`AkismetClient`] with [`AkismetClient::new()`].
#[derive(Debug)]
pub struct AkismetClient {
    /// The front page or home URL of the instance making the request
    ///
    /// For a blog, site, or wiki this would be the front page.
    /// Note: must be a full URI, including http://.
    pub blog: String,
    /// Akismet API key
    pub api_key: String,
    /// Instance of `reqwest::Client` to use for requests to Akismet
    pub client: Client,
    /// Akismet client configuration options
    pub options: AkismetOptions,
}

impl AkismetClient {
    /// Create a new [`AkismetClient`] for a given `blog` with an [`AkismetOptions`] configuration
    pub fn new(blog: String, api_key: String, client: Client, options: AkismetOptions) -> Self {
        Self {
            blog,
            api_key,
            client,
            options,
        }
    }

    /// Verify the validity of your Akismet API key
    pub async fn verify_key(&self) -> Result<(), Error> {
        let url = self.root_endpoint("verify-key");

        let verify_key = VerifyKey {
            key: &self.api_key,
            blog: &self.blog,
        };

        let res = self.post(&verify_key, url).await?;

        match res.text.as_str() {
            "valid" => Ok(()),
            "invalid" => match res.debug {
                Some(debug_text) => Err(Error::Invalid(debug_text.into())),
                None => Err(Error::Invalid("Unexpected invalid".into())),
            },
            text => Err(Error::UnexpectedResponse(text.into())),
        }
    }

    /// Check a [`Comment`] for spam
    pub async fn check_comment(&self, comment: Comment<'_>) -> Result<CheckResult, Error> {
        let url = self.api_endpoint("comment-check");

        let res = self.post(&comment, url).await?;

        match res.text.as_str() {
            "true" => match res.pro_tip.as_deref() {
                Some("discard") => Ok(CheckResult::Discard),
                Some(_) | None => Ok(CheckResult::Spam),
            },
            "false" => Ok(CheckResult::Ham),
            "invalid" => match res.debug {
                Some(debug_text) => Err(Error::Invalid(debug_text.into())),
                None => Err(Error::Invalid("Unexpected invalid".into())),
            },
            text => Err(Error::UnexpectedResponse(text.into())),
        }
    }

    /// Submit a [`Comment`] as spam
    pub async fn submit_spam(&self, comment: Comment<'_>) -> Result<(), Error> {
        let url = self.api_endpoint("submit-spam");

        match self.post(&comment, url).await?.text.as_str() {
            "Thanks for making the web a better place." => Ok(()),
            text => Err(Error::UnexpectedResponse(text.into())),
        }
    }

    /// Submit a [`Comment`] as not spam
    pub async fn submit_ham(&self, comment: Comment<'_>) -> Result<(), Error> {
        let url = self.api_endpoint("submit-ham");

        match self.post(&comment, url).await?.text.as_str() {
            "Thanks for making the web a better place." => Ok(()),
            text => Err(Error::UnexpectedResponse(text.into())),
        }
    }

    async fn post(&self, req: &impl Serialize, url: String) -> Result<AkismetResponse, Error> {
        let req = self
            .client
            .post(url)
            .body(serde_qs::to_string(&req)?)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::USER_AGENT, &self.options.user_agent);

        let rsp = req.send().await?;

        match rsp.status().is_success() {
            true => Ok(AkismetResponse {
                pro_tip: match rsp.headers().get(AKISMET_PRO_TIP_HEADER) {
                    Some(header) => Some(header.to_str()?.to_string()),
                    None => None,
                },
                debug: match rsp.headers().get(AKISMET_DEBUG_HEADER) {
                    Some(header) => Some(header.to_str()?.to_string()),
                    None => None,
                },
                text: rsp.text().await?,
            }),
            false => match rsp.headers().get(AKISMET_ERROR_HEADER) {
                Some(header) => Err(Error::AkismetError(header.to_str()?.into())),
                None => {
                    let error_text = rsp.text().await?;
                    Err(Error::AkismetError(error_text))
                }
            },
        }
    }

    fn root_endpoint(&self, path: &str) -> String {
        format!(
            "{}://{}/{}/{}",
            &self.options.protocol, &self.options.host, &self.options.version, path
        )
    }

    fn api_endpoint(&self, path: &str) -> String {
        format!(
            "{}://{}.{}/{}/{}",
            &self.options.protocol, &self.api_key, &self.options.host, &self.options.version, path
        )
    }
}

/// A set of configuration options for an [`AkismetClient`]
#[derive(Debug)]
pub struct AkismetOptions {
    /// Host for Akismet API endpoint
    pub host: String,
    /// Protocol for Akismet API endpoint
    pub protocol: String,
    /// Akismet version
    pub version: String,
    /// User agent of Akismet library
    pub user_agent: String,
}

impl Default for AkismetOptions {
    fn default() -> Self {
        Self {
            host: AKISMET_HOST.to_string(),
            protocol: AKISMET_PROTOCOL.to_string(),
            version: AKISMET_VERSION.to_string(),
            user_agent: format!(
                "Instant-Akismet/{} | Akismet/{}",
                env!("CARGO_PKG_VERSION"),
                AKISMET_VERSION
            ),
        }
    }
}

/// An Akismet comment
///
/// <https://akismet.com/development/api/#comment-check>
#[derive(Debug, Serialize)]
pub struct Comment<'a> {
    /// The front page or home URL of the instance making the request
    ///
    /// For a blog or wiki this would be the front page.
    /// Note: must be a full URI, including http://.
    pub blog: &'a str,
    /// IP address of the comment submitter
    pub user_ip: &'a str,
    /// User agent string of the web browser submitting the comment
    ///
    /// Note: not to be confused with the user agent of your Akismet library.
    pub user_agent: Option<&'a str>,
    /// The content of the HTTP_REFERER header (note spelling)
    pub referrer: Option<&'a str>,
    /// The full permanent URL of the entry the comment was submitted to
    pub permalink: Option<&'a str>,
    /// A string that describes the type of content being sent
    ///
    /// Serialized from [`CommentType`] enum.
    pub comment_type: Option<CommentType>,
    /// Name submitted with the comment
    pub comment_author: Option<&'a str>,
    /// Email address submitted with the comment
    pub comment_author_email: Option<&'a str>,
    /// URL submitted with comment
    ///
    /// Only send a URL that was manually entered by the user, not an automatically generated URL.
    pub comment_author_url: Option<&'a str>,
    /// The content that was submitted
    pub comment_content: Option<&'a str>,
    #[serde(with = "ts_seconds_option")]
    /// The UTC timestamp of the creation of the comment, in ISO 8601 format
    ///
    /// May be omitted for comment-check requests if the comment is sent to the API on creation.
    pub comment_date_gmt: Option<DateTime<Utc>>,
    #[serde(with = "ts_seconds_option")]
    /// The UTC timestamp of the publication time for the content on which the comment was posted
    pub comment_post_modified_gmt: Option<DateTime<Utc>>,
    /// Indicates the language(s) in use on the blog or site, in ISO 639-1 format, comma-separated
    ///
    /// A site with articles in English and French might use “en, fr_ca”.
    pub blog_lang: Option<&'a str>,
    /// Character encoding for the values included in `comment_*` parameters
    ///
    /// eg: “UTF-8” or “ISO-8859-1”
    pub blog_charset: Option<&'a str>,
    /// The user role of the user who submitted the comment
    ///
    /// If you set it to “administrator”, Akismet will always return false.
    pub user_role: Option<&'a str>,
    /// Use when submitting test queries to Akismet
    pub is_test: Option<bool>,
    /// Reason for sending content to Akismet to be rechecked
    ///
    /// Include `recheck_reason` with a string describing why the content is being rechecked.
    /// For example, `recheck_reason=edit`.
    pub recheck_reason: Option<&'a str>,
    /// Name of a honeypot field
    ///
    /// For example, if you have a honeypot field like `<input name="hidden_honeypot_field"/>`,
    /// you should set this to `hidden_honeypot_field`.
    pub honeypot_field_name: Option<&'a str>,
    /// If `honeypot_field_name` is defined, you should include that input field's value here.
    pub hidden_honeypot_field: Option<&'a str>,
}

impl<'a> Comment<'a> {
    /// Create a minimal [`Comment`] with the required `blog` and `user_ip`
    pub fn new(blog: &'a str, user_ip: &'a str) -> Self {
        Self {
            blog,
            user_ip,
            user_agent: None,
            referrer: None,
            permalink: None,
            comment_type: None,
            comment_author: None,
            comment_author_email: None,
            comment_author_url: None,
            comment_content: None,
            comment_date_gmt: None,
            comment_post_modified_gmt: None,
            blog_lang: None,
            blog_charset: None,
            user_role: None,
            is_test: None,
            recheck_reason: None,
            honeypot_field_name: None,
            hidden_honeypot_field: None,
        }
    }

    /// Set the comment's `user_agent`
    pub fn user_agent(mut self, user_agent: &'a str) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// Set the comment's `referrer`
    pub fn referrer(mut self, referrer: &'a str) -> Self {
        self.referrer = Some(referrer);
        self
    }

    /// Set the comment's `permalink`
    pub fn permalink(mut self, permalink: &'a str) -> Self {
        self.permalink = Some(permalink);
        self
    }

    /// Set the comment's `comment_type`
    pub fn comment_type(mut self, comment_type: CommentType) -> Self {
        self.comment_type = Some(comment_type);
        self
    }

    /// Set the comment's `comment_author`
    pub fn comment_author(mut self, comment_author: &'a str) -> Self {
        self.comment_author = Some(comment_author);
        self
    }

    /// Set the comment's `comment_author_email`
    pub fn comment_author_email(mut self, comment_author_email: &'a str) -> Self {
        self.comment_author_email = Some(comment_author_email);
        self
    }

    /// Set the comment's `comment_author_url`
    pub fn comment_author_url(mut self, comment_author_url: &'a str) -> Self {
        self.comment_author_url = Some(comment_author_url);
        self
    }

    /// Set the comment's `comment_content`
    pub fn comment_content(mut self, comment_content: &'a str) -> Self {
        self.comment_content = Some(comment_content);
        self
    }

    /// Set the comment's `comment_date_gmt`
    pub fn comment_date_gmt(mut self, comment_date_gmt: DateTime<Utc>) -> Self {
        self.comment_date_gmt = Some(comment_date_gmt);
        self
    }

    /// Set the comment's `comment_post_modified_gmt`
    pub fn comment_post_modified_gmt(mut self, comment_post_modified_gmt: DateTime<Utc>) -> Self {
        self.comment_post_modified_gmt = Some(comment_post_modified_gmt);
        self
    }

    /// Set the comment's `blog_lang`
    pub fn blog_lang(mut self, blog_lang: &'a str) -> Self {
        self.blog_lang = Some(blog_lang);
        self
    }

    /// Set the comment's `blog_charset`
    pub fn blog_charset(mut self, blog_charset: &'a str) -> Self {
        self.blog_charset = Some(blog_charset);
        self
    }

    /// Set the comment's `user_role`
    pub fn user_role(mut self, user_role: &'a str) -> Self {
        self.user_role = Some(user_role);
        self
    }

    /// Set the comment's `is_test`
    pub fn is_test(mut self, is_test: bool) -> Self {
        self.is_test = Some(is_test);
        self
    }

    /// Set the comment's `recheck_reason`
    pub fn recheck_reason(mut self, recheck_reason: &'a str) -> Self {
        self.recheck_reason = Some(recheck_reason);
        self
    }

    /// Set the comment's `honeypot_field_name`
    pub fn honeypot_field_name(mut self, honeypot_field_name: &'a str) -> Self {
        self.honeypot_field_name = Some(honeypot_field_name);
        self
    }

    /// Set the comment's `hidden_honeypot_field`
    pub fn hidden_honeypot_field(mut self, hidden_honeypot_field: &'a str) -> Self {
        self.hidden_honeypot_field = Some(hidden_honeypot_field);
        self
    }
}

/// Type of content to be checked
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommentType {
    /// A blog comment
    Comment,
    /// A top-level forum post
    ForumPost,
    /// A reply to a top-level forum post
    Reply,
    /// A blog post
    BlogPost,
    /// A contact form or feedback form submission
    ContactForm,
    /// A new user account
    Signup,
    /// A message sent between users
    Message,
}

/// Result of an [`AkismetClient::check_comment()`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckResult {
    /// Not spam
    Ham,
    /// Spam
    Spam,
    /// Guaranteed spam (via pro-tip header)
    ///
    /// "If the X-akismet-pro-tip header is set to discard, then Akismet has determined that the
    /// comment is blatant spam, and you can safely discard it without saving it in any spam
    /// queue. Read more about this feature in [this Akismet blog
    /// post](http://blog.akismet.com/2014/04/23/theres-a-ninja-in-your-akismet/)."
    Discard,
}

struct AkismetResponse {
    text: String,
    pro_tip: Option<String>,
    debug: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyKey<'a> {
    key: &'a str,
    blog: &'a str,
}

/// Error type for instant-akismet
#[derive(Debug, Error)]
pub enum Error {
    /// Akismet responded with `invalid`
    #[error("Akismet request invalid: {0}")]
    Invalid(Cow<'static, str>),
    /// Akismet returned an unexpected response
    #[error("Unexpected response from Akismet: {0}")]
    UnexpectedResponse(String),
    /// Error in request to Akismet
    #[error("Akismet error: {0}")]
    AkismetError(String),
    /// Failed to serialize request
    #[error("{0}")]
    Serialize(#[from] serde_qs::Error),
    /// Reqwest client error
    #[error("{0}")]
    Reqwest(#[from] reqwest::Error),
    /// Failed to convert `HeaderValue` to string
    #[error("{0}")]
    ToStrError(#[from] reqwest::header::ToStrError),
    /// Miscellaneous errors
    #[error("{0}")]
    String(String),
}

const AKISMET_HOST: &str = "rest.akismet.com";
const AKISMET_PROTOCOL: &str = "https";
const AKISMET_VERSION: &str = "1.1";
const AKISMET_DEBUG_HEADER: &str = "x-akismet-debug-help";
const AKISMET_PRO_TIP_HEADER: &str = "x-akismet-pro-tip";
const AKISMET_ERROR_HEADER: &str = "x-akismet-alert-msg";

#[cfg(test)]
mod tests {
    use std::env;
    use std::error::Error;

    use crate::{AkismetClient, AkismetOptions, CheckResult, Comment};
    use reqwest::Client;

    #[tokio::test]
    async fn verify_client_key() -> Result<(), Box<dyn Error>> {
        let akismet_key = match env::var("AKISMET_KEY") {
            Ok(value) => value,
            Err(_) => panic!("AKISMET_KEY environment variable is not set."),
        };

        let akismet_client = AkismetClient::new(
            String::from("https://instantdomains.com"),
            akismet_key,
            Client::new(),
            AkismetOptions::default(),
        );

        akismet_client.verify_key().await?;

        Ok(())
    }

    #[tokio::test]
    async fn check_known_spam() -> Result<(), Box<dyn Error>> {
        let akismet_key = match env::var("AKISMET_KEY") {
            Ok(value) => value,
            Err(_) => panic!("AKISMET_KEY environment variable is not set."),
        };

        let akismet_client = AkismetClient::new(
            String::from("https://instantdomains.com"),
            akismet_key,
            Client::new(),
            AkismetOptions::default(),
        );

        let known_spam = Comment::new(akismet_client.blog.as_ref(), "8.8.8.8")
            .comment_author("viagra-test-123")
            .comment_author_email("akismet-guaranteed-spam@example.com")
            .comment_content("akismet-guaranteed-spam");

        let is_spam = akismet_client.check_comment(known_spam).await?;

        assert_ne!(is_spam, CheckResult::Ham);

        Ok(())
    }

    #[tokio::test]
    async fn check_known_ham() -> Result<(), Box<dyn Error>> {
        let akismet_key = match env::var("AKISMET_KEY") {
            Ok(value) => value,
            Err(_) => panic!("AKISMET_KEY environment variable is not set."),
        };

        let akismet_client = AkismetClient::new(
            String::from("https://instantdomains.com"),
            akismet_key,
            Client::new(),
            AkismetOptions::default(),
        );

        let known_ham = Comment::new(akismet_client.blog.as_ref(), "8.8.8.8")
            .comment_author("testUser1")
            .comment_author_email("test-user@example.com")
            .is_test(true);

        let is_spam = akismet_client.check_comment(known_ham).await.unwrap();

        assert_eq!(is_spam, CheckResult::Ham);

        Ok(())
    }

    #[tokio::test]
    async fn submit_spam() -> Result<(), Box<dyn Error>> {
        let akismet_key = match env::var("AKISMET_KEY") {
            Ok(value) => value,
            Err(_) => panic!("AKISMET_KEY environment variable is not set."),
        };

        let akismet_client = AkismetClient::new(
            String::from("https://instantdomains.com"),
            akismet_key,
            Client::new(),
            AkismetOptions::default(),
        );

        let spam = Comment::new(akismet_client.blog.as_ref(), "8.8.8.8")
            .comment_author("viagra-test-123")
            .comment_author_email("akismet-guaranteed-spam@example.com")
            .comment_content("akismet-guaranteed-spam");

        akismet_client.submit_spam(spam).await.unwrap();

        Ok(())
    }

    #[tokio::test]
    async fn submit_ham() -> Result<(), Box<dyn Error>> {
        let akismet_key = match env::var("AKISMET_KEY") {
            Ok(value) => value,
            Err(_) => panic!("AKISMET_KEY environment variable is not set."),
        };

        let akismet_client = AkismetClient::new(
            String::from("https://instantdomains.com"),
            akismet_key,
            Client::new(),
            AkismetOptions::default(),
        );

        let ham = Comment::new(akismet_client.blog.as_ref(), "8.8.8.8")
            .comment_author("testUser1")
            .comment_author_email("test-user@example.com");

        akismet_client.submit_ham(ham).await.unwrap();

        Ok(())
    }
}
