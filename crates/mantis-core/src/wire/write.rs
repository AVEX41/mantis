use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Write `raw` to `w` unchanged and flush.
///
/// No header is added, removed or recalculated (including `Content-Length`),
/// so malformed requests reach the target as written.
pub async fn write_raw<W: AsyncWrite + Unpin>(w: &mut W, raw: &[u8]) -> std::io::Result<()> {
    w.write_all(raw).await?;
    w.flush().await
}
