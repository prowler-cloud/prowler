import "server-only";

export default async function getProvider() {
  const res = await fetch("http://localhost:3000/api/providers");
  const product = await res.json();

  return product;
}
