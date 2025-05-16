// composables/useApiFetch.ts
import { useAuthStore } from "~/store/auth";
import type { UseFetchOptions } from "#app";

export function useApiFetch<T>(
  path: string | (() => string),
  options: UseFetchOptions<T> = {}
) {
  const config = useRuntimeConfig();
  const authStore = useAuthStore();
  const toast = useToast();

  const defaults: UseFetchOptions<T> = {
    baseURL: config.public.apiBaseUrl as string,

    onRequest({ options }) {
      if (authStore.getAccessToken) {
        const headers = new Headers(options.headers);
        headers.set("Authorization", `Bearer ${authStore.getAccessToken}`);
        options.headers = headers;
      }
    },

    async onResponseError({ request, response, options: fetchOptions }) {
      const originalPath = typeof path === "function" ? path() : path;

      if (response.status === 401 && originalPath !== "/auth/refresh") {
        authStore.setLoading(true);
        console.warn(
          `API Fetch: 401 Unauthorized for ${originalPath}. Attempting token refresh.`
        );

        try {
          const refreshResponse = await $fetch<{
            accessToken: string;
            refreshToken: string;
          }>(`${config.public.apiBaseUrl}/auth/refresh`, {
            method: "POST",
            ignoreResponseError: true,
            credentials: "include",
          });

          if (refreshResponse.accessToken) {
            authStore.setAuthData(
              authStore.currentUser,
              refreshResponse.accessToken
            );

            const newHeaders = new Headers(fetchOptions.headers);
            newHeaders.set(
              "Authorization",
              `Bearer ${refreshResponse.accessToken}`
            );

            const newOptions = {
              ...fetchOptions,
              headers: newHeaders,
            };
            authStore.setLoading(false);
            return $fetch(request, newOptions as any);
          } else {
            console.error(
              "Failed to refresh token. Server did not return new access token."
            );
            toast.add({
              title: "Session Error",
              description: "The token refresh failed (no new token received).",
              color: "error",
            });
            await authStore.logout("/login?refresh_failed_no_new_token=true");
          }
        } catch (refreshError: any) {
          console.error(
            "Error during token refresh attempt:",
            refreshError.data?.message || refreshError
          );
          if (
            refreshError.response &&
            (refreshError.response.status === 401 ||
              refreshError.response.status === 403)
          ) {
            toast.add({
              title: "Invalid Session",
              description:
                "The refresh token is invalid or expired. Please log in again.",
              color: "error",
            });
            await authStore.logout(
              "/login?refresh_token_invalid_on_retry=true"
            );
          } else {
            toast.add({
              title: "Network Error",
              description: "Couldn't reach the server for token refresh.",
              color: "warning",
            });
          }
        } finally {
          authStore.setLoading(false);
        }
      }
    },
  };

  return useFetch(path, { ...defaults, ...options });
}

export const $apiFetch = <T>(
  path: string,
  options: UseFetchOptions<T> = {}
) => {
  const config = useRuntimeConfig();
  const authStore = useAuthStore();

  const finalHeaders = new Headers(options.headers as HeadersInit);

  if (authStore.getAccessToken) {
    finalHeaders.set("Authorization", `Bearer ${authStore.getAccessToken}`);
  }

  const defaultSimpleOptions: UseFetchOptions<T> = {
    onResponseError: async ({ response }) => {
      if (
        response.status === 401 &&
        path !== "/auth/refresh" &&
        path !== "/auth/login"
      ) {
        console.warn(
          `$apiFetch (simple): 401 Unauthorized for ${path}. Automatic refresh not handled by this wrapper. Consider using useApiFetch or handling refresh manually.`
        );
      }
    },
  };

  const fetchOptions: UseFetchOptions<T> = {
    ...defaultSimpleOptions,
    ...options,
    baseURL: config.public.apiBaseUrl as string,
    headers: finalHeaders,
    credentials: "include",
  };

  return $fetch<T>(path, fetchOptions as any);
};
