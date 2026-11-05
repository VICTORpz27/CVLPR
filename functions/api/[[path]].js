
export async function onRequest(context) {
  return context.env.BACKEND.fetch(context.request);
}
