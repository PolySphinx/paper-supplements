use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use polysphinx::{
    node::Command,
    poly::{Golle, GolleAes, ImprovedLwe, Polyfication, Rise, Symmetric},
    DestinationAddress, Header, Identifier, MixNode, Path, PolySphinx, Scalar,
};
use rand::prelude::*;
use sphinxcrypto::{
    client::PathHop,
    commands::{NextHop, RoutingCommand},
};
use std::time::Duration;
use x25519_dalek_ng::PublicKey;

struct PolySphinxBencher<P> {
    polysphinx: PolySphinx<P, Identifier, (), DestinationAddress>,
    nodes: Vec<MixNode>,
}

impl PolySphinxBencher<Rise> {
    fn rise() -> Self {
        PolySphinxBencher::new(Rise)
    }
}

impl PolySphinxBencher<ImprovedLwe> {
    fn lwe() -> Self {
        PolySphinxBencher::new(ImprovedLwe::new(&mut thread_rng(), 10, 10))
    }
}

impl PolySphinxBencher<Golle> {
    fn golle() -> Self {
        PolySphinxBencher::new(Golle)
    }
}

impl PolySphinxBencher<GolleAes> {
    fn golle_aes() -> Self {
        PolySphinxBencher::new(GolleAes::new(10))
    }
}

impl PolySphinxBencher<Symmetric> {
    fn symmetric() -> Self {
        PolySphinxBencher::new(Symmetric)
    }
}

impl<P: Polyfication> PolySphinxBencher<P> {
    fn new(encrypter: P) -> Self {
        let mut rng = &mut thread_rng();
        let polysphinx = PolySphinx::new(5, 5, encrypter);
        let nodes: Vec<_> = (0..20).map(|_| MixNode::random(&mut rng)).collect();
        PolySphinxBencher { polysphinx, nodes }
    }

    fn random_path(&self) -> (&Scalar, Path<Identifier, (), DestinationAddress>) {
        let path = (0..5)
            .map(|_| self.nodes.choose(&mut thread_rng()).unwrap())
            .collect::<Vec<_>>();
        let first_key = path[0].priv_key.as_ref().unwrap();
        let path = path
            .into_iter()
            .map(|n| ((n.identifier, n.pub_key), ()))
            .collect::<Vec<_>>();
        (first_key, Path::Direct(path, [0; 48]))
    }

    #[inline]
    fn create_polyheader(&self, path: &Path<Identifier, (), DestinationAddress>) {
        self.polysphinx
            .create_polyheader(&mut thread_rng(), path)
            .unwrap();
    }

    #[inline]
    fn prepare_message(&self, payload: &[u8]) -> (Header, Vec<u8>, &Scalar) {
        let (first_key, path) = self.random_path();
        let (header, key) = self
            .polysphinx
            .create_polyheader(&mut thread_rng(), &path)
            .unwrap();
        let encrypted = self
            .polysphinx
            .polyfier()
            .encrypt(&mut thread_rng(), &key, payload)
            .unwrap();
        (header, encrypted, first_key)
    }

    #[inline]
    fn unwrap_header(&self, header: &Header, data: &[u8], priv_key: &Scalar) {
        let command = self.polysphinx.unwrap_header(priv_key, &header).unwrap();
        if let Command::Relay(r) = command {
            self.polysphinx
                .polyfier()
                .recrypt(&mut thread_rng(), &r.pre_key, data)
                .unwrap();
        } else {
            panic!("Non-relay command");
        }
    }
}

fn bench_create_header(c: &mut Criterion) {
    let mut group = c.benchmark_group("create_header");
    /*
        let ps_rise = PolySphinxBencher::rise();
        let path = ps_rise.random_path();
        group.bench_function("PolySphinx/RISE", |b| {
            b.iter(|| ps_rise.create_polyheader(&path))
        });

        let ps_lwe = PolySphinxBencher::lwe();
        let path = ps_lwe.random_path();
        group.bench_function("PolySphinx/LWE", |b| {
            b.iter(|| ps_lwe.create_polyheader(&path))
        });

        let ps_golle = PolySphinxBencher::golle();
        let path = ps_golle.random_path();
        group.bench_function("PolySphinx/Golle", |b| {
            b.iter(|| ps_golle.create_polyheader(&path))
        });

        let ps_golle_aes = PolySphinxBencher::golle_aes();
        let path = ps_golle_aes.random_path();
        group.bench_function("PolySphinx/GolleAes", |b| {
            b.iter(|| ps_golle_aes.create_polyheader(&path))
        });
    */
    let ps_sym = PolySphinxBencher::symmetric();
    let (_, path) = ps_sym.random_path();
    group.bench_function("PolySphinx", |b| b.iter(|| ps_sym.create_polyheader(&path)));

    let path = (0..4)
        .map(|_| {
            let mut public_bytes = [0u8; 32];
            for i in &mut public_bytes {
                *i = thread_rng().gen();
            }
            let public_key = PublicKey::from(public_bytes);
            PathHop {
                id: [0; 32],
                public_key,
                commands: Some(vec![RoutingCommand::NextHop(NextHop {
                    id: [0; 32],
                    mac: [0; 16],
                })]),
            }
        })
        .collect::<Vec<_>>();
    group.bench_function("sphinxcrypto", |b| {
        b.iter(|| sphinxcrypto::client::create_header(&mut thread_rng(), path.clone()))
    });

    group.finish();
}

fn bench_unwrap(c: &mut Criterion) {
    let mut group = c.benchmark_group("unwrap_header");
    let payload = include_bytes!("payload.txt");

    for size in [512, 1024, 2*1024, 3*1024, 4*1024, 5*1024, 6*1024, 7*1024, 8*1024] {
        let payload = &payload[..size];
        group.throughput(Throughput::Bytes(size as u64));
        /*
                let ps_rise = PolySphinxBencher::rise();
                let (header, encrypted, node) = ps_rise.prepare_message(payload);
                group.bench_with_input(BenchmarkId::new("PolySphinx/RISE", size), &size, |b, _| {
                    b.iter(|| ps_rise.unwrap_header(&header, &encrypted, &node))
                });

                let ps_lwe = PolySphinxBencher::lwe();
                let (header, encrypted, node) = ps_lwe.prepare_message(payload);
                group.bench_with_input(BenchmarkId::new("PolySphinx/LWE", size), &size, |b, _| {
                    b.iter(|| ps_lwe.unwrap_header(&header, &encrypted, &node))
                });

                let ps_golle = PolySphinxBencher::golle();
                let (header, encrypted, node) = ps_golle.prepare_message(payload);
                group.bench_with_input(BenchmarkId::new("PolySphinx/Golle", size), &size, |b, _| {
                    b.iter(|| ps_golle.unwrap_header(&header, &encrypted, &node))
                });

                let ps_golle_aes = PolySphinxBencher::golle_aes();
                let (header, encrypted, node) = ps_golle_aes.prepare_message(payload);
                group.bench_with_input(BenchmarkId::new("PolySphinx/GolleAes", size), &size, |b, _| {
                    b.iter(|| ps_golle_aes.unwrap_header(&header, &encrypted, &node))
                });
        */
        let ps_sym = PolySphinxBencher::symmetric();
        let (header, encrypted, node) = ps_sym.prepare_message(payload);
        group.bench_with_input(BenchmarkId::new("PolySphinx", size), &size, |b, _| {
            b.iter(|| ps_sym.unwrap_header(&header, &encrypted, &node))
        });

        let (packet, private_key) = sphinxcrypto_packet_creator::create_packet(payload);
        group.bench_with_input(BenchmarkId::new("sphinxcrypto", size), &size, |b, _| {
            b.iter(|| {
                black_box(sphinxcrypto::server::sphinx_packet_unwrap(
                    &private_key,
                    &mut packet.clone(),
                ))
            })
        });
    }

    group.finish();
}

mod sphinxcrypto_packet_creator {
    use super::*;
    use sphinxcrypto::client::{new_packet, PathHop};
    use sphinxcrypto::commands::{Delay, Recipient, RoutingCommand, SURBReply};
    use sphinxcrypto::constants::{MAX_HOPS, NODE_ID_SIZE, RECIPIENT_ID_SIZE, SURB_ID_SIZE};
    use x25519_dalek_ng::StaticSecret;

    struct NodeParams {
        pub id: [u8; NODE_ID_SIZE],
        pub private_key: StaticSecret,
    }

    fn new_node<R: Rng + CryptoRng>(rng: &mut R) -> NodeParams {
        let mut id = [0u8; NODE_ID_SIZE];
        rng.fill_bytes(&mut id);
        let keypair = StaticSecret::new(rng);
        return NodeParams {
            id,
            private_key: keypair,
        };
    }

    fn new_path_vector<R: Rng + CryptoRng>(
        rng: &mut R,
        num_hops: u8,
        is_surb: bool,
    ) -> (Vec<NodeParams>, Vec<PathHop>) {
        const DELAY_BASE: u32 = 123;

        // Generate the keypairs and node identifiers for the "nodes".
        let mut nodes = vec![];
        let mut i = 0;
        while i < num_hops {
            nodes.push(new_node(rng));
            i += 1;
        }

        // Assemble the path vector.
        let mut path = vec![];
        i = 0;
        while i < num_hops {
            let mut commands: Vec<RoutingCommand> = vec![];
            if i < num_hops - 1 {
                // Non-terminal hop, add the delay.
                let delay = RoutingCommand::Delay(Delay {
                    delay: DELAY_BASE * (i as u32 + 1),
                });
                commands.push(delay);
            } else {
                // Terminal hop, add the recipient.
                let mut rcpt_id = [0u8; RECIPIENT_ID_SIZE];
                rng.fill_bytes(&mut rcpt_id);
                let rcpt = RoutingCommand::Recipient(Recipient { id: rcpt_id });
                commands.push(rcpt);

                if is_surb {
                    let mut surb_id = [0u8; SURB_ID_SIZE];
                    rng.fill_bytes(&mut surb_id);
                    let surb_reply = RoutingCommand::SURBReply(SURBReply { id: surb_id });
                    commands.push(surb_reply);
                }
            }
            let hop = PathHop {
                id: nodes[i as usize].id,
                public_key: PublicKey::from(&nodes[i as usize].private_key),
                commands: Some(commands),
            };
            path.push(hop);
            i += 1;
        }
        return (nodes, path);
    }

    pub fn create_packet(payload: &[u8]) -> (Vec<u8>, StaticSecret) {
        let mut r = thread_rng();
        let is_surb = false;
        let (nodes, path) = new_path_vector(&mut r, MAX_HOPS as u8, is_surb);

        let packet = new_packet(&mut r, path, payload.to_vec()).unwrap();
        (packet, nodes[0].private_key.clone())
    }
}

criterion_group! {
    name=benches;
    config=Criterion::default()
        .measurement_time(Duration::from_secs(20))
        .sample_size(400);
    targets=bench_create_header, bench_unwrap
}
criterion_main!(benches);
