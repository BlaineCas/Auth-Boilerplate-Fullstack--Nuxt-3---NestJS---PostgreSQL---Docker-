export default defineNuxtConfig({
  devtools: { enabled: true },
  modules: ["@nuxt/ui-pro", "@pinia/nuxt"],
  css: ["~/assets/css/main.css"],
  runtimeConfig: {
    public: {
      apiBaseUrl:
        process.env.NUXT_PUBLIC_API_BASE_URL || "http://localhost:3000/api",
      googleClientId: process.env.NUXT_PUBLIC_GOOGLE_CLIENT_ID || "",
    },
  },
  ssr: false,
  nitro: {
    devProxy: {
      "/api": {
        target: "http://localhost:3000",
        changeOrigin: true,
        cookieDomainRewrite: {
          "*": "",
        },
      },
    },
  },
});
