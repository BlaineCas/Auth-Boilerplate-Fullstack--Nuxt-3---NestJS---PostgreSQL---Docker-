// middleware/auth.global.ts
import { useAuthStore, type User } from "~/store/auth"; // Importă User dacă e necesar aici

export default defineNuxtRouteMiddleware(async (to, from) => {
  const authStore = useAuthStore();
  const nuxtApp = useNuxtApp();

  if (import.meta.client && !authStore.isAuthReady) {
    if (!authStore.isLoading) {
      await authStore.fetchUserOnLoad();
    }
    if (!authStore.isAuthReady) {
      await new Promise((resolve) => {
        const unwatch = watch(
          () => authStore.isAuthReady,
          (isReady) => {
            if (isReady) {
              unwatch();
              resolve(true);
            }
          }
        );
      });
    }
  }

  const requiresAuth = to.matched.some(
    (record) =>
      record.meta.requiresAuth !== false &&
      (to.path.startsWith("/app") || record.meta.requiresAuth === true)
  );

  const guestPages = [
    "/login",
    "/register",
    "/forgot-password",
    "/reset-password",
  ];
  const isGuestPage =
    guestPages.includes(to.path) ||
    to.path.startsWith("/auth/verify-email") ||
    to.path.startsWith("/login-success");

  if (requiresAuth && !authStore.isAuthenticated) {
    console.log(
      `Auth middleware: Path "${to.path}" requires auth. User not authenticated. Redirecting to login.`
    );
    return navigateTo(`/login?redirect=${encodeURIComponent(to.fullPath)}`, {
      replace: true,
    });
  }

  if (isGuestPage && authStore.isAuthenticated) {
    console.log(
      `Auth middleware: Path "${to.path}" is a guest page. User authenticated. Redirecting to dashboard.`
    );
    return navigateTo("/app/dashboard", { replace: true });
  }

  if (import.meta.client) {
    if (to.path === "/login-success") {
      const { token, user: userData, refreshToken } = to.query;
      if (token && userData && refreshToken) {
        try {
          const user = JSON.parse(
            decodeURIComponent(userData as string)
          ) as User;
          authStore.setAuthData(user, token as string);
          authStore.setAuthReady(true);

          const redirectQuery =
            nuxtApp?._route?.query?.redirect ||
            nuxtApp?.vueApp?.config?.globalProperties?.$route?.query?.redirect;
          const redirectPath = redirectQuery
            ? decodeURIComponent(redirectQuery as string)
            : "/app/dashboard";
          return navigateTo(redirectPath, { replace: true });
        } catch (e) {
          console.error("Error processing OAuth callback data:", e);
          return navigateTo("/login?error=oauth_processing_failed", {
            replace: true,
          });
        }
      } else if (to.query.error) {
        console.error("OAuth login failed on server:", to.query.error);
      }
    } else if (to.path === "/auth/verify-email") {
      const { token } = to.query;
      if (token) {
      } else {
        return navigateTo("/login?error=verification_token_missing", {
          replace: true,
        });
      }
    }
  }
});
