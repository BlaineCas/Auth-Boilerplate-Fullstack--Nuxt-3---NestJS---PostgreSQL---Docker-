<template>
    <div class="min-h-screen text-white selection:text-white">
        <NuxtLoadingIndicator />
        <header class="bg-default/75 backdrop-blur border-b border-default sticky top-0 z-50 p-4">
            <UContainer class="flex justify-between items-center">
                <NuxtLink to="/app/dashboard"
                    class="text-2xl font-bold text-primary-400 hover:text-primary-300 transition-colors flex items-center">
                    <Icon name="i-tabler-alien" size="1.5em" class="mr-1"/>
                    Boilerplate
                </NuxtLink>
                <div v-if="authStore.currentUser" class="flex items-center space-x-4">
                    <UPopover mode="hover">
                        <UButton color="primary" variant="ghost" class="flex items-center">
                            <UAvatar :src="authStore.currentUser.avatarUrl || undefined"
                                :alt="authStore.currentUser.lastName ? authStore.currentUser.lastName[0] + (authStore.currentUser.lastName ? authStore.currentUser.lastName[0] : '') : authStore.currentUser.email[0]"
                                size="sm" imgClass="object-cover" />
                            <span class="ml-2 text-sm hidden md:inline">{{ authStore.currentUser.lastName ||
                                authStore.currentUser.email.split('@')[0] }}</span>
                            <UIcon name="i-heroicons-chevron-down-20-solid" class="w-5 h-5 transition-transform" />
                        </UButton>
                        <template #content>
                            <div class="p-2 border border-gray-700 rounded-md shadow-lg">
                                <UButton label="Profile (soon)" icon="i-heroicons-user-circle" color="neutral"
                                    variant="ghost" class="w-full text-left mb-1" disabled />
                                <UButton @click="handleLogout" label="Logout" icon="i-heroicons-arrow-left-on-rectangle"
                                    color="primary" variant="ghost" class="w-full text-left cursor-pointer" />
                            </div>
                        </template>
                    </UPopover>
                </div>
            </UContainer>
        </header>
        <main class="p-4 md:p-6 lg:p-8">
            <UContainer>
                <NuxtPage />
            </UContainer>
        </main>
    </div>
</template>

<script setup lang="ts">
import { useAuthStore } from '~/store/auth';
const authStore = useAuthStore();

useHead({
    titleTemplate: (titleChunk) => {
        return titleChunk ? `${titleChunk} - App | Boilerplate` : 'App | Boilerplate';
    }
})

const handleLogout = async () => {
    await authStore.logout(); 
};
</script>
  
