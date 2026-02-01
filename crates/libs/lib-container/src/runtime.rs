mod runtime {
	tonic::include_proto!("runtime.v1");
}

use crate::error::Result;
use hyper_util::rt::TokioIo;
use runtime::runtime_service_client::RuntimeServiceClient;
pub use runtime::*;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;

pub(crate) type K8sRtServiceClient = RuntimeServiceClient<tonic::transport::Channel>;

pub(crate) async fn connect() -> Result<K8sRtServiceClient> {
	let endpoint = tonic::transport::Endpoint::from_static("http://[::]");

	let channel = endpoint
		.connect_with_connector(service_fn(|_: Uri| async {
			let stream = tokio::net::UnixStream::connect("/run/containerd/containerd.sock").await?;
			Ok::<_, std::io::Error>(TokioIo::new(stream))
		}))
		.await?;

	Ok(RuntimeServiceClient::new(channel))
}
