use async_recursion::async_recursion;

use crate::{Node, Result, persist::DynLoaderSaver};

#[async_recursion]
pub async fn walk_node(path: Vec<u8>, l: &mut Option<DynLoaderSaver>, n: &mut Node) -> Result<()> {
    if n.forks.is_empty() {
        n.load(l).await?;
    }

    // err := walkNodeFnCopyBytes(ctx, path, n, nil, walkFn)
	// if err != nil {
	// 	return err
	// }

    for (_, v) in n.forks.iter_mut() {
        let mut next_path = path.clone();
        next_path.extend_from_slice(&v.prefix);

        walk_node(next_path, l, &mut v.node).await?
    }

    Ok(())
}