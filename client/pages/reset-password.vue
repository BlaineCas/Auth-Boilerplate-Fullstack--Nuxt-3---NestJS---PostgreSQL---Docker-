<template>
    <UCard class="w-full max-w-md mt-16 mx-auto">
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
import { z } from 'zod';
import { useAuthStore } from '~/store/auth';
import type { FormSubmitEvent } from '#ui/types'; 

useHead({ title: 'Resset Password' });
definePageMeta({ layout: 'default' });

const authStore = useAuthStore();
const router = useRouter();
const route = useRoute();
const toast = useToast();

const token = ref<string | null>(null);
const passwordHint = "Minimum 8 characters, one uppercase letter, one lowercase letter, one digit, and one special character.";

onMounted(() => {
    if (typeof route.query.token === 'string' && route.query.token) {
        token.value = route.query.token;
    } else {
        toast.add({
            title: 'Parameter Error',
            description: 'Reset token is missing from the URL.',
            color: 'error',
            icon: 'i-heroicons-exclamation-circle',
            duration: 7000
        });
    }
});

const schema = z.object({
    newPassword: z.string()
        .min(8, 'Password must be at least 8 characters.')
        .max(50, 'Password can have a maximum of 50 characters.')
        .regex(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, passwordHint),
    confirmNewPassword: z.string().min(8, 'Password confirmation is required.'),
}).refine(data => data.newPassword === data.confirmNewPassword, {
    message: "Passwords do not match.",
    path: ["confirmNewPassword"],
});

type Schema = z.output<typeof schema>;

const fields = [{
    name: 'newPassword',
    label: 'Password',
    type: 'password' as const,
    placeholder: 'Enter your password'
}, {
    name: 'confirmNewPassword',
    label: 'Repeat Password',
    type: 'password' as const,
    placeholder: 'Enter your password'
}]

const handleSubmit = async (payload: FormSubmitEvent<Schema>) => {
    if (!token.value || authStore.isLoading) return;
    authStore.setLoading(true);
    try {
        await $apiFetch('/auth/reset-password', {
            method: 'POST',
            body: {
                token: token.value,
                newPassword: payload.data.newPassword,
            },
        });
        toast.add({
            title: 'Password Reset!',
            description: 'Your password has been successfully changed. You can now log in with your new password.',
            color: 'success',
            icon: 'i-heroicons-check-circle',
            duration: 7000
        });

        router.push('/login?password_reset_success=true');
    } catch (error: any) {
        console.error('Reset password error:', error.data);
        toast.add({
            title: 'Reset Error',
            description: error.data?.message || 'Invalid or expired token, or another error occurred. Please try the reset request again.',
            color: 'error',
            icon: 'i-heroicons-exclamation-circle',
            duration: 7000,
        });
    } finally {
        authStore.setLoading(false);
    }
};
</script>
  
