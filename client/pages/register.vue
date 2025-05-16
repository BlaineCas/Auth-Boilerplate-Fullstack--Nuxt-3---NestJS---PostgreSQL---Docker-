<template>
    <UCard class="w-full max-w-md mt-16 mx-auto" >
        <div class="flex flex-col items-center justify-center gap-4 p-4">
            <UAuthForm class="max-w-md mx-auto" title="Boilerplate" description="Register" icon="i-tabler-alien"
                :fields="fields" :schema="schema" :submit-button="{ label: 'Register', color: 'primary', block: true }"
                @submit="handleSubmit">
                <template #footer>
                    <div class="text-sm text-center space-y-2">
                        <p class="text-gray-400">
                            Do you have an account?
                            <NuxtLink to="/login"
                                class="font-medium text-primary-400 hover:text-primary-300 transition-colors">
                                Login
                            </NuxtLink>
                        </p>
                    </div>
                </template>
            </UAuthForm>
        </div>
    </UCard>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { z } from 'zod';
import { useAuthStore } from '~/store/auth';
import type { FormSubmitEvent } from '#ui/types'; 

useHead({ title: 'Register | Boilerplate' });
definePageMeta({
    layout: 'default',
});

const authStore = useAuthStore();
const router = useRouter();
const config = useRuntimeConfig();
const toast = useToast();

const googleLoading = ref(false);
const passwordHint = "Minimum 8 characters, one uppercase letter, one lowercase letter, one number, and one special character.";

// Zod Schema for validation
const passwordValidation = z.string()
    .min(8, 'Password must be at least 8 characters long.')
    .max(50, 'Password can be at most 50 characters long.')
    .regex(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_]).{8,}$/, passwordHint);

const schema = z.object({
    email: z.string().email('Invalid email address.').trim(),
    password: passwordValidation,
    confirmPassword: z.string().min(1, 'Password confirmation is required.'),
}).refine(data => data.password === data.confirmPassword, {
    message: "Passwords do not match.",
    path: ["confirmPassword"],
});

type Schema = z.output<typeof schema>;

const fields = [{
    name: 'email',
    type: 'text' as const,
    label: 'Email',
    placeholder: 'Enter your email',
    required: true
}, {
    name: 'password',
    label: 'Password',
    type: 'password' as const,
    placeholder: 'Enter your password'
}, {
    name: 'confirmPassword',
    label: 'Repeat Password',
    type: 'password' as const,
    placeholder: 'Enter your password'
}]

const handleSubmit = async (payload: FormSubmitEvent<Schema>) => {
    if (authStore.isLoading) return;
    authStore.setLoading(true);

    try {
        const payloadObj = {
            email: payload.data.email,
            password: payload.data.password,
        };

        await $apiFetch('/auth/register', {
            method: 'POST',
            body: payloadObj,
        });

        toast.add({
            title: 'Account Created!',
            description: 'A verification email has been sent. Check your inbox (and Spam) to activate your account.',
            color: 'success',
            icon: 'i-heroicons-check-circle',
            duration: 10000,
        });

        router.push('/login?verification_sent=true');

    } catch (error: any) {
        toast.add({
            title: 'Registration Error',
            description: error.data?.message || 'An error occurred. Please try again.',
            color: 'error',
            icon: 'i-heroicons-exclamation-circle',
            duration: 6000,
        });
    } finally {
        authStore.setLoading(false);
    }
};

const handleGoogleLogin = () => {
    if (googleLoading.value) return;
    googleLoading.value = true;
    try {
        const googleAuthUrl = `${config.public.apiBaseUrl}/auth/google`;
        window.location.href = googleAuthUrl;
    } catch (error) {
        toast.add({
            title: 'Google Login Error',
            description: 'Google authentication could not be initiated.',
            color: 'error',
        });
        googleLoading.value = false;
    }
};
</script>