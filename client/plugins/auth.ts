import { useAuthStore } from "~/store/auth";

export default defineNuxtPlugin(async (nuxtApp) => {
  const authStore = useAuthStore();

  if (import.meta.client) {
    if (!authStore.isAuthReady && !authStore.isLoading) {
      await authStore.fetchUserOnLoad();
    } else if (authStore.isLoading) {
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

  // Optional: You can provide helper functions or the store instance to the Nuxt context
  // if it needs to be accessed directly via nuxtApp.$auth in other parts of the application.
  // return {
  //   provide: {
  //     auth: authStore // Ex. accesibil ca nuxtApp.$auth
  //   }
  // }
});
