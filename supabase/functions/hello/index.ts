Deno.serve(async (req) => {
  let name = "anonymous";

  if (req.body) {
    try {
      const body = await req.json();
      if (body.name) {
        name = body.name;
      }
    } catch {
      // If body isn't valid JSON, keep default name
    }
  }

  return new Response(
    JSON.stringify({ message: `Hello ${name}!` }),
    { headers: { "Content-Type": "application/json" } },
  );
});
