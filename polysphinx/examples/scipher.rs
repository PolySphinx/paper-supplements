use polysphinx::*;

use rand::seq::IteratorRandom;

use std::collections::{HashMap, HashSet};

fn generate_random_path(
    nodes: &HashMap<Identifier, MixNode>,
    level: u32,
) -> Path<Identifier, u32, DestinationAddress> {
    let path = (0..2)
        .map(|_| nodes.values().choose(&mut rand::thread_rng()).unwrap())
        .map(|node| ((node.identifier, node.pub_key), 13u32))
        .collect::<Vec<_>>();
    if level == 0 {
        Path::Direct(path, [0; 48])
    } else {
        let subpaths = (0..5)
            .map(|_| {
                let subpath = generate_random_path(nodes, level - 1);
                (*subpath.first(), subpath)
            })
            .collect::<Vec<_>>();
        Path::Multi(path, subpaths)
    }
}

fn handle<P: Polyfication>(
    polysphinx: &PolySphinx<P, Identifier, u32, DestinationAddress>,
    node: &MixNode,
    header: Header,
    data: &[u8],
) -> Vec<(Identifier, Header, Vec<u8>)> {
    println!("Node {:?} received a message", node.identifier);
    println!("    Header size: {}", header.pack().len());

    let mut rng = rand::thread_rng();
    let msg = polysphinx
        .unwrap_header(&node.priv_key.unwrap(), &header)
        .unwrap();
    match msg {
        node::Command::Relay(r) => {
            println!("Extra data: {:?}", r.extra_data);
            let new_data = polysphinx
                .recrypt_payload(&mut rng, &r.pre_key, data)
                .unwrap();
            assert_eq!(data.len(), new_data.len());
            dbg!(data.len());
            vec![(r.next_hop, r.next_header, new_data)]
        }

        node::Command::Destination(d) => {
            println!("Header Payload: {:?}", d.recipient);
            let plain = polysphinx
                .decrypt_payload(&mut rng, &d.decryption_key, data)
                .unwrap();
            println!(
                "\x1B[32mMessage Payload: {}\x1B[0m",
                std::str::from_utf8(&plain).unwrap()
            );
            vec![]
        }

        node::Command::Multicast(m) => {
            println!("Multicast:");
            m.subheaders
                .into_iter()
                .map(|r| {
                    println!("-> {:?}", &r.next_hop);
                    (
                        r.next_hop,
                        r.next_header,
                        polysphinx
                            .recrypt_payload(&mut rng, &r.pre_key, data)
                            .unwrap(),
                    )
                })
                .collect()
        }
    }
}

fn main() {
    run(PolySphinx::new(2, 5))
}

fn run<P: Polyfication>(polysphinx: PolySphinx<P, Identifier, u32, DestinationAddress>) {
    let mut rng = rand::thread_rng();
    let mut nodes: HashMap<Identifier, MixNode> = HashMap::new();

    for _ in 0..20 {
        let node = MixNode::random(&mut rng);
        nodes.insert(node.identifier, node);
    }
    println!("I've generated {} mix nodes", nodes.len());

    let path = generate_random_path(&nodes, 1);
    let (message, initial) = polysphinx.create_polyheader(&mut rng, &path).unwrap();

    println!("\x1B[33mHeader size: {} bits\x1B[0m", message.pack().len());
    println!("    Beta length: {}", message.beta.len());

    println!("Please enter a message:");
    let mut text = String::new();
    std::io::stdin().read_line(&mut text).unwrap();
    let text = text.as_bytes();
    let encrypted = polysphinx
        .prepare_payload(&mut rng, &initial, text)
        .unwrap();

    let mut queue = vec![(path.first().0 .0, message, encrypted)];

    let mut seen_messages: HashSet<Vec<u8>> = HashSet::new();
    while !queue.is_empty() {
        let (identifier, header, data) = queue.remove(0);

        if seen_messages.contains(&data) {
            println!("\x1B[31mMessages seen twice!\x1B[0m");
        }
        seen_messages.insert(data.clone());

        let node = &nodes[&identifier];
        queue.extend(handle(&polysphinx, node, header, &data));
    }
}
