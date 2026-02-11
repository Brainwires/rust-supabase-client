Deno.serve(async (req) => {
  let body = null;

  if (req.body) {
    try {
      body = await req.json();
    } catch {
      // If body isn't valid JSON, try text
      try {
        body = await req.text();
      } catch {
        body = null;
      }
    }
  }

  return new Response(
    JSON.stringify({
      method: req.method,
      body,
    }),
    { headers: { "Content-Type": "application/json" } },
  );
});
