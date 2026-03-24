export class NextResponse {
  static redirect(url: string | URL) {
    return new Response(null, {
      status: 302,
      headers: { Location: String(url) },
    });
  }
  static json(body: unknown, init?: ResponseInit) {
    return new Response(JSON.stringify(body), init);
  }
}
export class NextRequest extends Request {}
