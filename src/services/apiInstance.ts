"use server";

import { revalidateTag } from "next/cache";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

// Helper to normalize headers
function normalizeHeaders(h?: HeadersInit): Record<string, string> {
  if (!h) return {};

  // Check for Headers by presence of .entries() method
  if (h && typeof (h as any).entries === "function") {
    return Object.fromEntries((h as Headers).entries());
  }

  // Array of [key, value] tuples
  if (Array.isArray(h)) return Object.fromEntries(h);

  // Plain object
  return h as Record<string, string>;
}

// Helper to detect plain objects for automatic JSON stringify
function isPlainObject(obj: any): boolean {
  return (
    typeof obj === "object" &&
    obj !== null &&
    Object.prototype.toString.call(obj) !== "[object FormData]" &&
    Object.prototype.toString.call(obj) !== "[object ArrayBuffer]"
  );
}

// Server-side fetch wrapper
export async function apiFetch(
  url: string,
  options: RequestInit & {
    includeAuth?: boolean;
    params?: Record<string, string | string[] | undefined>;
    revalidateTags?: string[];
    ignore401Redirect?: boolean;
  } = {},
) {
  const baseURL = process.env.BASE_URL!;

  // Build query string from params
  let fullUrl = baseURL + url;
  if (options.params) {
    const queryString = new URLSearchParams(
      Object.entries(options.params).reduce(
        (acc, [key, value]) => {
          if (value !== undefined) {
            acc[key] = Array.isArray(value) ? value.join(",") : value;
          }
          return acc;
        },
        {} as Record<string, string>,
      ),
    ).toString();

    if (queryString) {
      fullUrl += (url.includes("?") ? "&" : "?") + queryString;
    }
  }

  const includeAuth = options.includeAuth !== false;

  // Check if body is FormData to skip setting Content-Type
  const isFormData = options.body instanceof FormData;

  let headers: Record<string, string> = {
    Accept: "application/json",
    ...normalizeHeaders(options.headers),
  };

  // Only set Content-Type for non-FormData requests
  if (!isFormData) {
    headers["Content-Type"] = "application/json";
  }

  const cookieStore = await cookies();
  const token = cookieStore.get(process.env.AUTH_TOKEN_KEY || "token")?.value;
  const lang = cookieStore.get("lang")?.value || "ar";

  if (includeAuth && token) headers["Authorization"] = `Bearer ${token}`;
  headers["Accept-Language"] = lang;

  // Automatically stringify plain object bodies (but not FormData)
  let body: any = options.body;
  if (body && !isFormData && isPlainObject(body)) {
    body = JSON.stringify(body);
  }

  try {
    const res = await fetch(fullUrl, {
      ...options,
      headers,
      body,
    });

    // revalidate tags
    if (options.revalidateTags) {
      options.revalidateTags.forEach((tag: string) => {
        revalidateTag(tag, "default");
      });
    }

    if (res.status === 401 && !options.ignore401Redirect) {
      throw {
        unauthorized: true,
        redirect: "/",
        message: "انتهت صلاحية الجلسة، يرجى تسجيل الدخول مرة أخرى",
      };
    }

    return await handleResponse(res);
  } catch (err: any) {
    console.log(err, "error from apiInstance");

    if (err.unauthorized) {
      redirect("/api/auth/deleteCookie");
    }

    // throw err;
    return err;
  }
}

// Response handler
async function handleResponse(res: Response) {
  const contentType = res.headers.get("content-type");

  if (!res.ok) {
    const body = contentType?.includes("json")
      ? await res.json()
      : await res.text();
    throw { status: res.status, body };
  }

  return contentType?.includes("json") ? await res.json() : await res.text();
}
