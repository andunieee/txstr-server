use ritualistic::management::{Method, call};
use ritualistic::{Event, EventTemplate, Filter, Kind, Relay, SecretKey, Tags, Timestamp};

struct Running {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start(dir: &std::path::Path, admin: &SecretKey, no_images: bool) -> Running {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let options = server::Options {
        data_dir: dir.to_path_buf(),
        admins: vec![admin.pubkey()],
        no_images,
    };
    let task = tokio::spawn(async move {
        server::serve(options, listener).await.unwrap();
    });
    Running { url, task }
}

fn event(sk: &SecretKey, kind: u16, content: &str, tags: Vec<Vec<String>>) -> Event {
    EventTemplate {
        created_at: Timestamp::now(),
        kind: Kind(kind),
        tags: Tags(tags),
        content: content.to_string(),
    }
    .finalize(sk)
}

/// publish and return the rejection message, if any
async fn publish(url: &str, event: Event) -> Result<(), String> {
    let relay = Relay::connect(url.parse().unwrap(), None).await.unwrap();
    relay.publish(event).await.map_err(|err| err.to_string())
}

async fn manage(url: &str, admin: &SecretKey, method: Method) -> serde_json::Value {
    call(url, admin, &method).await.unwrap()
}

async fn count(url: &str, filter: Filter) -> usize {
    let network = ritualistic::Network::new();
    network
        .query(vec![url.to_string()], filter, Default::default())
        .await
        .len()
}

#[tokio::test]
async fn whitelist_and_follows() {
    let dir = tempfile::tempdir().unwrap();
    let admin = SecretKey::generate();
    let s = start(dir.path(), &admin, false).await;

    let alice = SecretKey::generate();
    let bob = SecretKey::generate();
    let carol = SecretKey::generate();

    // nobody but the admin can write at first
    let err = publish(&s.url, event(&alice, 1, "hi", vec![]))
        .await
        .unwrap_err();
    assert!(err.contains("restricted"), "{err}");
    publish(&s.url, event(&admin, 1, "hi", vec![]))
        .await
        .unwrap();

    // whitelist alice
    manage(
        &s.url,
        &admin,
        Method::AllowPubKey(alice.pubkey(), Some("friend".into())),
    )
    .await;
    publish(&s.url, event(&alice, 1, "hi", vec![]))
        .await
        .unwrap();
    let listed = manage(&s.url, &admin, Method::ListAllowedPubKeys).await;
    assert_eq!(
        listed,
        serde_json::json!([{"pubkey": alice.pubkey().to_hex(), "reason": "friend"}])
    );

    // alice follows bob, so bob can write, but carol (followed by bob) still can't
    publish(
        &s.url,
        event(&alice, 3, "", vec![vec!["p".into(), bob.pubkey().to_hex()]]),
    )
    .await
    .unwrap();
    publish(
        &s.url,
        event(&bob, 3, "", vec![vec!["p".into(), carol.pubkey().to_hex()]]),
    )
    .await
    .unwrap();
    publish(&s.url, event(&bob, 1, "hey", vec![]))
        .await
        .unwrap();
    assert!(
        publish(&s.url, event(&carol, 1, "yo", vec![]))
            .await
            .is_err()
    );

    // reads are open to everybody
    assert_eq!(
        count(
            &s.url,
            Filter {
                kinds: Some(vec![Kind(1)]),
                ..Default::default()
            }
        )
        .await,
        3
    );

    // removing alice from the whitelist also removes the people she follows
    manage(&s.url, &admin, Method::UnallowPubKey(alice.pubkey(), None)).await;
    assert!(
        publish(&s.url, event(&alice, 1, "hi again", vec![]))
            .await
            .is_err()
    );
    assert!(
        publish(&s.url, event(&bob, 1, "hey again", vec![]))
            .await
            .is_err()
    );

    // strangers can't manage
    assert!(
        call(&s.url, &alice, &Method::AllowPubKey(carol.pubkey(), None))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn no_images() {
    let dir = tempfile::tempdir().unwrap();
    let admin = SecretKey::generate();
    let s = start(dir.path(), &admin, true).await;

    let img = "look https://example.com/cat.png";
    let err = publish(&s.url, event(&admin, 1, img, vec![]))
        .await
        .unwrap_err();
    assert!(err.contains("images"), "{err}");
    assert!(
        publish(&s.url, event(&admin, 1111, img, vec![]))
            .await
            .is_err()
    );

    // other kinds and text without images are fine
    publish(&s.url, event(&admin, 1, "https://example.com/page", vec![]))
        .await
        .unwrap();
    publish(
        &s.url,
        event(&admin, 30023, img, vec![vec!["d".into(), "x".into()]]),
    )
    .await
    .unwrap();

    // and with the option off, images are accepted
    drop(s);
    let s = start(dir.path(), &admin, false).await;
    publish(&s.url, event(&admin, 1, img, vec![]))
        .await
        .unwrap();
}

#[tokio::test]
async fn kinds_bans_and_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let admin = SecretKey::generate();
    let s = start(dir.path(), &admin, false).await;

    // disallowed kinds
    manage(&s.url, &admin, Method::DisallowKind(Kind(7))).await;
    assert!(
        publish(&s.url, event(&admin, 7, "+", vec![]))
            .await
            .is_err()
    );
    assert_eq!(
        manage(&s.url, &admin, Method::ListDisallowedKinds).await,
        serde_json::json!([7])
    );

    // an allow list restricts to only those
    manage(&s.url, &admin, Method::AllowKind(Kind(1))).await;
    publish(&s.url, event(&admin, 1, "ok", vec![]))
        .await
        .unwrap();
    assert!(
        publish(&s.url, event(&admin, 1111, "no", vec![]))
            .await
            .is_err()
    );

    // banning an event deletes it and keeps it out
    let ev = event(&admin, 1, "regrettable", vec![]);
    publish(&s.url, ev.clone()).await.unwrap();
    let by_id = || Filter {
        ids: Some(vec![ev.id]),
        ..Default::default()
    };
    assert_eq!(count(&s.url, by_id()).await, 1);
    manage(&s.url, &admin, Method::BanEvent(ev.id, Some("oops".into()))).await;
    assert_eq!(count(&s.url, by_id()).await, 0);
    let err = publish(&s.url, ev.clone()).await.unwrap_err();
    assert!(err.contains("banned"), "{err}");

    // metadata
    manage(&s.url, &admin, Method::ChangeRelayName("renamed".into())).await;
    manage(
        &s.url,
        &admin,
        Method::ChangeRelayDescription("about".into()),
    )
    .await;
    let info = ritualistic::relay_information::fetch(&s.url).await.unwrap();
    assert_eq!(
        (info.name.as_str(), info.description.as_str()),
        ("renamed", "about")
    );

    // everything survives a restart
    drop(s);
    let s = start(dir.path(), &admin, false).await;
    let info = ritualistic::relay_information::fetch(&s.url).await.unwrap();
    assert_eq!(info.name, "renamed");
    assert!(publish(&s.url, ev).await.is_err());
    assert!(
        publish(&s.url, event(&admin, 7, "+", vec![]))
            .await
            .is_err()
    );

    // ip blocking (we're connecting from localhost)
    manage(
        &s.url,
        &admin,
        Method::BlockIP("127.0.0.1".parse().unwrap(), None),
    )
    .await;
    assert!(Relay::connect(s.url.parse().unwrap(), None).await.is_err());
}

#[tokio::test]
async fn default_name() {
    let dir = tempfile::tempdir().unwrap();
    let admin = SecretKey::generate();
    let s = start(dir.path(), &admin, false).await;
    let info = ritualistic::relay_information::fetch(&s.url).await.unwrap();
    assert_eq!(info.name, "txstr server");
    assert_eq!(info.pubkey, Some(admin.pubkey()));
}
