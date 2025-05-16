<template>
    <div
        class="min-h-screen text-white flex flex-col items-center justify-center p-4 selection:bg-primary-500 selection:text-white">
        <NuxtLoadingIndicator />
        <NuxtPage />
    </div>
</template>
<script setup lang="ts">
useHead({
    titleTemplate: (titleChunk) => { 
        return titleChunk ? `${titleChunk} - Boilerplate` : 'Boilerplate';
    },
    htmlAttrs: {
        lang: 'en' 
    }
})
</script>
  
