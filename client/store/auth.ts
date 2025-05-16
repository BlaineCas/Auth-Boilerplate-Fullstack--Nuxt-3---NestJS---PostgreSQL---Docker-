// store/auth.ts
import { defineStore } from "pinia";
import { $apiFetch } from "~/composables/useApiFetch";

export interface User {
  id: string;
  email: string;
  firstName?: string | null;
  lastName?: string | null;
  avatarUrl?: string | null;
  role: string;
  isEmailVerified: boolean;
}

interface AuthState {
  user: User | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  loading: boolean;
  authReady: boolean;
}

export const useAuthStore = defineStore("auth", {
  state: (): AuthState => ({
    user: null,
    accessToken: null,
    isAuthenticated: false,
    loading: false,
    authReady: false,
  }),
  getters: {
    currentUser: (state) => state.user,
    getAccessToken: (state) => state.accessToken,
    isAuth: (state) => state.isAuthenticated,
    isLoading: (state) => state.loading,
    isAuthReady: (state) => state.authReady,
  },
  actions: {
    setLoading(loading: boolean) {
      this.loading = loading;
    },
    setAuthReady(ready: boolean) {
      this.authReady = ready;
    },
    setAuthData(user: User | null, accessToken: string | null) {
      this.user = user;
      this.accessToken = accessToken;
      this.isAuthenticated = !!(user && accessToken);
    },
    async logout(redirectTo: string = "/login") {
      this.setLoading(true);
      try {
        if (this.accessToken) {
          await $apiFetch("/auth/logout", { method: "POST" });
        }
      } catch (error) {
        console.error(
          "Logout failed on server, clearing client-side session anyway:",
          error
        );
      } finally {
        this.setAuthData(null, null);
        this.setLoading(false);
        this.setAuthReady(true);
        if (import.meta.client) {
          await navigateTo(redirectTo);
        }
      }
    },
    async fetchUserOnLoad() {
      if (this.isAuthenticated) {
        this.setAuthReady(true);
        return;
      }

      this.setLoading(true);
      try {
        const response = await $apiFetch<{
          accessToken: string;
          refreshToken: string;
        }>("/auth/refresh", {
          method: "POST",
          credentials: "include",
        });

        if (response.accessToken) {
          this.accessToken = response.accessToken;
          const userProfile = await $apiFetch<User>("/auth/profile", {
            method: "GET",
          });
          this.setAuthData(userProfile, response.accessToken);
        } else {
          await this.logout("/login?session_expired_on_load=true");
        }
      } catch (error: any) {
        console.error(
          "Failed to refresh session on load:",
          error.data?.message || error
        );
        if (error.response?.status === 401 || error.response?.status === 403) {
          await this.logout("/login?invalid_refresh_token=true");
        } else {
          this.setAuthData(null, null);
          console.warn(
            "Network or other error during fetchUserOnLoad, user remains unauthenticated."
          );
        }
      } finally {
        this.setLoading(false);
        this.setAuthReady(true);
      }
    },
  },
});
