use std::borrow::Cow;

use chrono::{serde::ts_seconds_option, DateTime, Utc};
use reqwest::Client;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug)]
pub struct AkismetClient {
    blog: String,
    api_key: String,
    client: Client,
    options: AkismetOptions,
}

impl AkismetClient {
    pub fn new(blog: String, api_key: String, client: Client, options: AkismetOptions) -> Self {
        Self {
            blog,
            api_key,
            client,
            options,
        }
    }

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

    pub async fn submit_spam(&self, comment: Comment<'_>) -> Result<(), Error> {
        let url = self.api_endpoint("submit-spam");

        match self.post(&comment, url).await?.text.as_str() {
            "Thanks for making the web a better place." => Ok(()),
            text => Err(Error::UnexpectedResponse(text.into())),
        }
    }

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

#[derive(Debug)]
pub struct AkismetOptions {
    host: String,
    protocol: String,
    version: String,
    user_agent: String,
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

#[derive(Debug, Serialize)]
pub struct Comment<'a> {
    blog: &'a str,
    user_ip: &'a str,
    user_agent: Option<&'a str>,
    referrer: Option<&'a str>,
    permalink: Option<&'a str>,
    comment_type: Option<CommentType>,
    comment_author: Option<&'a str>,
    comment_author_email: Option<&'a str>,
    comment_author_url: Option<&'a str>,
    comment_content: Option<&'a str>,
    #[serde(with = "ts_seconds_option")]
    comment_date_gmt: Option<DateTime<Utc>>,
    #[serde(with = "ts_seconds_option")]
    comment_post_modified_gmt: Option<DateTime<Utc>>,
    blog_lang: Option<&'a str>,
    blog_charset: Option<&'a str>,
    user_role: Option<&'a str>,
    is_test: Option<bool>,
    recheck_reason: Option<&'a str>,
    honeypot_field_name: Option<&'a str>,
    hidden_honeypot_field: Option<&'a str>,
}

impl<'a> Comment<'a> {
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

    pub fn user_agent(mut self, user_agent: &'a str) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn referrer(mut self, referrer: &'a str) -> Self {
        self.referrer = Some(referrer);
        self
    }

    pub fn permalink(mut self, permalink: &'a str) -> Self {
        self.permalink = Some(permalink);
        self
    }

    pub fn comment_type(mut self, comment_type: CommentType) -> Self {
        self.comment_type = Some(comment_type);
        self
    }

    pub fn comment_author(mut self, comment_author: &'a str) -> Self {
        self.comment_author = Some(comment_author);
        self
    }

    pub fn comment_author_email(mut self, comment_author_email: &'a str) -> Self {
        self.comment_author_email = Some(comment_author_email);
        self
    }

    pub fn comment_author_url(mut self, comment_author_url: &'a str) -> Self {
        self.comment_author_url = Some(comment_author_url);
        self
    }

    pub fn comment_content(mut self, comment_content: &'a str) -> Self {
        self.comment_content = Some(comment_content);
        self
    }

    pub fn comment_date_gmt(mut self, comment_date_gmt: DateTime<Utc>) -> Self {
        self.comment_date_gmt = Some(comment_date_gmt);
        self
    }

    pub fn comment_post_modified_gmt(mut self, comment_post_modified_gmt: DateTime<Utc>) -> Self {
        self.comment_post_modified_gmt = Some(comment_post_modified_gmt);
        self
    }

    pub fn blog_lang(mut self, blog_lang: &'a str) -> Self {
        self.blog_lang = Some(blog_lang);
        self
    }

    pub fn blog_charset(mut self, blog_charset: &'a str) -> Self {
        self.blog_charset = Some(blog_charset);
        self
    }

    pub fn user_role(mut self, user_role: &'a str) -> Self {
        self.user_role = Some(user_role);
        self
    }

    pub fn is_test(mut self, is_test: bool) -> Self {
        self.is_test = Some(is_test);
        self
    }

    pub fn recheck_reason(mut self, recheck_reason: &'a str) -> Self {
        self.recheck_reason = Some(recheck_reason);
        self
    }

    pub fn honeypot_field_name(mut self, honeypot_field_name: &'a str) -> Self {
        self.honeypot_field_name = Some(honeypot_field_name);
        self
    }

    pub fn hidden_honeypot_field(mut self, hidden_honeypot_field: &'a str) -> Self {
        self.hidden_honeypot_field = Some(hidden_honeypot_field);
        self
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommentType {
    Comment,
    ForumPost,
    Reply,
    BlogPost,
    ContactForm,
    Signup,
    Message,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckResult {
    Ham,
    Spam,
    Discard,
}

pub struct AkismetResponse {
    text: String,
    pro_tip: Option<String>,
    debug: Option<String>,
}

#[derive(Debug, Serialize)]
struct VerifyKey<'a> {
    key: &'a str,
    blog: &'a str,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Akismet request invalid: {0}")]
    Invalid(Cow<'static, str>),
    #[error("Unexpected response from Akismet: {0}")]
    UnexpectedResponse(String),
    #[error("Akismet error: {0}")]
    AkismetError(String),
    #[error("{0}")]
    Serialize(#[from] serde_qs::Error),
    #[error("{0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("{0}")]
    ToStrError(#[from] reqwest::header::ToStrError),
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
