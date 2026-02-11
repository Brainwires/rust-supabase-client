Deno.serve(async (req) => {
  if (req.body) {
    const data = await req.arrayBuffer();
    if (data.byteLength > 0) {
      return new Response(new Uint8Array(data), {
        headers: { "Content-Type": "application/octet-stream" },
      });
    }
  }

  // Default: return a known byte sequence
  const bytes = new Uint8Array([0, 1, 2, 3, 4, 5, 255]);
  return new Response(bytes, {
    headers: { "Content-Type": "application/octet-stream" },
  });
});
