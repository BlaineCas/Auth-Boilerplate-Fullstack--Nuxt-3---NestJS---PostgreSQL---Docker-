<template>
    <UCard class="w-full max-w-md bg-gray-800 shadow-xl text-center">
        <template #header>
            <div class="text-center">
                <UIcon v-if="isLoading || !verificationStatus" name="i-tabler-mail-cog"
                    class="text-5xl text-primary-500 mb-3 animate-pulse" />
                <UIcon v-else-if="verificationStatus === 'success'" name="i-tabler-mail-check"
                    class="text-5xl text-green-500 mb-3" />
                <UIcon v-else name="i-tabler-mail-cancel" class="text-5xl text-red-500 mb-3" />
                <h1 class="text-3xl font-bold text-white">Verify your email</h1>
            </div>
        </template>

        <div v-if="isLoading" class="py-8">
            <UIcon name="i-tabler-loader-2" class="animate-spin text-4xl text-primary-400" />
            <p class="mt-3 text-gray-300">The token is being verified....</p>
        </div>

        <div v-else-if="verificationStatus === 'success'" class="py-6">
            <p class="text-lg text-green-400">{{ message }}</p>
            <UButton v-if="authStore.isAuthenticated" to="/app/dashboard" label="Go to Dashboard" color="primary"
                size="lg" class="mt-6" />
            <UButton v-else to="/login?verified=true" label="Go to Login" color="primary" size="lg" class="mt-6" />
        </div>

        <div v-else-if="verificationStatus === 'error'" class="py-6">
            <p class="text-lg text-red-400">{{ message }}</p>
            <div class="mt-6 space-y-3">
                <UButton @click="resendVerification" :loading="resendLoading" label="Resend Verification Email"
                    color="info" variant="soft" size="md" :disabled="!userEmailForResend" />
                <UButton to="/login" label="Go to Login" color="neutral" variant="outline" size="md" />
            </div>
        </div>

        <div v-else-if="verificationStatus === 'no-token'" class="py-6">
            <p class="text-lg text-yellow-400">{{ message }}</p>
            <UButton to="/login" label="Go to Login" color="neutral" variant="outline" size="md" class="mt-6" />
        </div>
    </UCard>
</template>

<script setup lang="ts">
import { useAuthStore, type User } from '~/store/auth';

useHead({ title: 'Email Verification' });
definePageMeta({ layout: 'default' });

const route = useRoute();
const router = useRouter();
const authStore = useAuthStore();
const toast = useToast();

const isLoading = ref(true); 
const resendLoading = ref(false); 
const verificationStatus = ref<'success' | 'error' | 'no-token' | null>(null); 
const message = ref(''); 
const userEmailForResend = ref<string | null>(null);


onMounted(async () => {
    const token = route.query.token as string; 

    if (!token) { 
        message.value = 'Missing or invalid verification token. Please check the email link.';
        verificationStatus.value = 'no-token';
        isLoading.value = false;
        return;
    }

    try {
        const response = await $apiFetch<{ message: string; user?: User; accessToken?: string; refreshToken?: string }>('/auth/verify-email', {
            method: 'GET', 
            params: { token },
        });

        message.value = response.message || 'The email address has been verified successfully!';
        verificationStatus.value = 'success';

        if (response.user && response.accessToken && response.refreshToken) {
            authStore.setAuthData(response.user, response.accessToken);
            authStore.setAuthReady(true); 
        }

    } catch (error: any) {
        console.error('Email verification error:', error.data);
        message.value = error.data?.message || 'The verification email failed. The token may be invalid, expired, or already used.';
        verificationStatus.value = 'error';
        if (error.data?.email) { 
            userEmailForResend.value = error.data.email;
        } else if (authStore.currentUser?.email && !authStore.currentUser.isEmailVerified) {
            userEmailForResend.value = authStore.currentUser.email;
        }
    } finally {
        isLoading.value = false;
    }
});

const resendVerification = async () => {
    const emailToResend = userEmailForResend.value;

    if (!emailToResend) {
        toast.add({ title: 'Email Error', description: 'Email address not found. Please register again or contact support.', color: 'error', icon: 'i-heroicons-exclamation-circle', duration: 7000 });
        return;
    }

    resendLoading.value = true; 
    try {
        await $apiFetch('/auth/resend-verification-email', {
            method: 'POST',
            body: { email: emailToResend }
        });
        toast.add({ title: 'Email Retrimis!', description: 'A new verification email has been sent to the specified address. Check your inbox (and Spam folder).', color: 'success', icon: 'i-heroicons-check-circle', duration: 7000 });
        router.push('/login?verification_sent=true');
    } catch (error: any) {
        toast.add({ title: 'Error on Resend', description: error.data?.message || 'The verification email could not be resent. Please try again later.', color: 'error', icon: 'i-heroicons-exclamation-circle' });
    } finally {
        resendLoading.value = false;
    }
}
</script>
  
