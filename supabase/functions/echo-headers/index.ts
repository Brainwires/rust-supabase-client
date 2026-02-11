Deno.serve(async (req) => {
  const headers: Record<string, string> = {};
  req.headers.forEach((value, key) => {
    headers[key] = value;
  });

  return new Response(
    JSON.stringify({
      method: req.method,
      headers,
      url: req.url,
    }),
    { headers: { "Content-Type": "application/json" } },
  );
});
