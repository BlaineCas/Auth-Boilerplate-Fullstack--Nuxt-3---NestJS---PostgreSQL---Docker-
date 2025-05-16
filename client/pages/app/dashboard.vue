<template>
    <div>
        <UCard> <template #header>
                <div class="flex justify-between items-center">
                    <h2 class="text-2xl font-semibold text-white">Dashboard</h2>
                    <UBadge v-if="authStore.currentUser?.isEmailVerified" color="success" variant="soft" size="md">
                        <UIcon name="i-heroicons-check-badge" class="mr-1" />Verified Email
                    </UBadge>
                    <UBadge v-else color="warning" variant="soft" size="md">
                        <UIcon name="i-heroicons-exclamation-triangle" class="mr-1" />Unverified Email
                    </UBadge>
                </div>
            </template>

            <div v-if="authStore.currentUser" class="space-y-4">
                <p class="text-lg text-gray-300">Welcome back, <span class="font-semibold text-primary-400">{{
                        authStore.currentUser.lastName || authStore.currentUser.email.split('@')[0] }}</span>!</p>

                <div v-if="!authStore.currentUser.isEmailVerified"
                    class="p-4 bg-yellow-600/20 border border-yellow-500 rounded-md">
                    <p class="text-yellow-200 font-medium">Your email address is not verified</p>
                    <p class="text-yellow-300 text-sm mt-1">To access all the platform’s features, please check your
                        inbox (including the Spam folder) for the confirmation email.</p>
                    <UButton @click="handleResendVerification" :loading="resendLoading"
                        label="Retrimite email de verificare" color="warning" variant="link" size="sm"
                        class="mt-2 p-0" />
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <UCard>
                        <template #header>
                            <h3 class="text-base font-semibold leading-6 text-gray-100">Account Details</h3>
                        </template>
                        <dl class="divide-y divide-gray-700">
                            <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4">
                                <dt class="text-sm font-medium text-gray-400">User ID:</dt>
                                <dd class="mt-1 text-sm text-gray-200 sm:col-span-2 sm:mt-0 truncate"
                                    :title="authStore.currentUser.id">{{ authStore.currentUser.id }}</dd>
                            </div>
                            <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4">
                                <dt class="text-sm font-medium text-gray-400">Email:</dt>
                                <dd class="mt-1 text-sm text-gray-200 sm:col-span-2 sm:mt-0">{{
                                    authStore.currentUser.email }}</dd>
                            </div>
                            <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4">
                                <dt class="text-sm font-medium text-gray-400">First Name:</dt>
                                <dd class="mt-1 text-sm text-gray-200 sm:col-span-2 sm:mt-0">{{
                                    authStore.currentUser.firstName ||
                                    '-' }}</dd>
                            </div>
                            <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4">
                                <dt class="text-sm font-medium text-gray-400">Last Name:</dt>
                                <dd class="mt-1 text-sm text-gray-200 sm:col-span-2 sm:mt-0">{{
                                    authStore.currentUser.lastName ||
                                    '-' }}</dd>
                            </div>
                            <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4">
                                <dt class="text-sm font-medium text-gray-400">Role:</dt>
                                <dd class="mt-1 text-sm text-gray-200 sm:col-span-2 sm:mt-0">
                                    <UBadge color="primary" variant="subtle">{{ authStore.currentUser.role }}</UBadge>
                                </dd>
                            </div>
                        </dl>
                    </UCard>

                    <UCard>
                        <template #header>
                            <h3 class="text-base font-semibold leading-6 text-gray-100">Options (E.g)</h3>
                        </template>
                        <div class="space-y-3">
                            <UButton label="Schedule (soon)" icon="i-heroicons-calendar-days" block disabled />
                            <UButton label="Media (soon)" icon="i-heroicons-photo" block disabled />
                            <UButton label="Settings (soon)" icon="i-heroicons-cog-6-tooth" block disabled />
                        </div>
                    </UCard>
                </div>

            </div>
            <div v-else-if="authStore.isLoading || !authStore.isAuthReady" class="text-center py-10">
                <UIcon name="i-tabler-loader-2" class="animate-spin text-4xl text-primary-400" />
                <p class="mt-3 text-gray-300">The user data is being loaded....</p>
            </div>
            <div v-else class="text-center py-10">
                <p class="text-lg text-yellow-400">You are not logged in.</p>
                <UButton to="/login" label="Mergi la Autentificare" color="primary" class="mt-4" />
            </div>
        </UCard>
    </div>
</template>

<script setup lang="ts">
import { useAuthStore } from '~/store/auth';

definePageMeta({
    layout: 'app',
});

useHead({ title: 'Dashboard' });

const authStore = useAuthStore();
const toast = useToast();
const resendLoading = ref(false);

const handleResendVerification = async () => {
    if (!authStore.currentUser?.email) {
        toast.add({
            title: 'Email Error',
            description: 'Email address is not available for resending.',
            color: 'error',
            icon: 'i-heroicons-exclamation-circle'
        });
        return;
    }
    resendLoading.value = true; // Set loading state
    try {
        // Call backend endpoint to resend the verification email
        await $apiFetch('/auth/resend-verification-email', {
            method: 'POST',
            body: { email: authStore.currentUser.email }
        });
        toast.add({
            title: 'Email Resent!',
            description: 'A new verification email has been sent to your address. Check your inbox (and Spam folder).',
            color: 'success',
            icon: 'i-heroicons-check-circle',
            duration: 7000
        });
    } catch (error: any) {
        toast.add({
            title: 'Resend Error',
            description: error.data?.message || 'The verification email could not be resent. Please try again later.',
            color: 'error',
            icon: 'i-heroicons-exclamation-circle'
        });
    } finally {
        resendLoading.value = false; // Stop loading state
    }
}

// Ensure user data is loaded if navigating directly to this page.
// Although the middleware and plugin should handle this, an extra check on component mount
// can be helpful in certain scenarios (e.g., hot-reloading in development).
onMounted(async () => {
    if (authStore.isAuthReady && !authStore.isLoading) { // If state is not ready and not already loading
        await authStore.fetchUserOnLoad();
    }
    // If the user is still not authenticated after loading, the middleware should have already redirected.
    // An explicit redirect here is not necessary if middleware works correctly.
});
</script>
  
