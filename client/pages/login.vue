<template>
    <UCard class="w-full max-w-md mt-16 mx-auto">
        <div class="flex flex-col items-center justify-center gap-4 p-4">
            <UAuthForm class="max-w-md mx-auto" title="Boilerplate" description="Login"
                icon="i-tabler-alien" :fields="fields" :providers="providers" :schema="schema"
                :loading="authStore.isLoading || googleLoading"
                :submit-button="{ label: 'Autentificare', color: 'primary', block: true }" @submit="handleSubmit">
                <template #footer>
                    <div class="text-sm text-center space-y-2">
                        <NuxtLink to="/forgot-password"
                            class="text-primary-400 hover:text-primary-300 transition-colors">
                            Forgot password?
                        </NuxtLink>
                        <p class="text-gray-400">
                            Don't have an account?
                            <NuxtLink to="/register"
                                class="font-medium text-primary-400 hover:text-primary-300 transition-colors">
                                Sign up
                            </NuxtLink>
                        </p>
                    </div>
                    <div v-if="route.query.error"
                        class="mt-4 p-3 bg-red-700 border border-red-600 text-red-100 rounded-md text-sm text-center">
                        {{ getErrorMessage(route.query.error as string) }}
                    </div>
                    <div v-if="sessionExpired"
                        class="mt-4 p-3 bg-yellow-700 border border-yellow-600 text-yellow-100 rounded-md text-sm text-center">
                        Session expired. Please log in again.
                    </div>
                    <div v-if="route.query.verified === 'true'"
                        class="mt-4 p-3 bg-green-700 border border-green-600 text-green-100 rounded-md text-sm text-center">
                        Email verified successfully! You can now log in.
                    </div>
                    <div v-if="route.query.password_reset_success === 'true'"
                        class="mt-4 p-3 bg-green-700 border border-green-600 text-green-100 rounded-md text-sm text-center">
                        The Password has been reset successfully! You can now log in with the new password.
                    </div>
                    <div v-if="route.query.verification_sent === 'true'"
                        class="mt-4 p-3 bg-blue-700 border border-blue-600 text-blue-100 rounded-md text-sm text-center">
                        An email with a verification link has been sent to your email address. Please check your inbox (Spam folder).
                    </div>
                </template>
            </UAuthForm>
        </div>
    </UCard>
</template>

<script setup lang="ts">
import { z } from 'zod'
import { useAuthStore, type User } from '~/store/auth'
import type { FormSubmitEvent } from '#ui/types'; 

useHead({ title: 'Login' })
definePageMeta({ layout: 'default' })

const authStore = useAuthStore()
const router = useRouter()
const route = useRoute()
const toast = useToast()

const googleLoading = ref(false)

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
}]

const providers = [{
    label: 'Google',
    icon: 'i-simple-icons-google',
    onClick: () => {
        toast.add({ title: 'Google', description: 'Login with Google'})
    }
}]

const schema = z.object({
    email: z.string().email('Invalid email'),
    password: z.string().min(8, 'Must be at least 8 characters')
})

type Schema = z.output<typeof schema>

const getErrorMessage = (errorCode: string) => {
    switch (errorCode) {
        case 'oauth_processing_failed':
            return 'An error occurred while processing the external authentication data.'
        case 'google_auth_failed':
            return 'Google authentication failed.'
        case 'verification_token_missing':
            return 'Verification token missing. Contact support.'
        case 'verification_failed':
            return 'Email verification failed. Invalid or expired token.'
        case 'reset_token_invalid':
            return 'Password reset token is invalid or has expired.'
        default:
            return 'An unknown authentication error occurred.'
    }
}

const handleSubmit = async (payload: FormSubmitEvent<Schema>) => {
    if (authStore.isLoading) return
    authStore.setLoading(true)
    try {
        const response = await $apiFetch<{ accessToken: string; refreshToken: string; user: User }>('/auth/login', {
            method: 'POST',
            body: payload.data,
            credentials: 'include'
        })
        authStore.setAuthData(response.user, response.accessToken)
        authStore.setAuthReady(true)

        toast.add({
            title: 'Login Successful!',
            description: `Welcome, ${response.user.lastName || response.user.email}!`,
            color: 'success',
            icon: 'i-heroicons-check-circle',
        })

        const redirectPath = route.query.redirect ? decodeURIComponent(route.query.redirect as string) : '/app/dashboard'
        router.push(redirectPath)
    } catch (error: any) {
        console.error('Login error:', error.data)
        toast.add({
            title: 'Authentication Error',
            description: error.data?.message || 'Check the entered email address and password.',
            color: 'error',
            icon: 'i-heroicons-exclamation-circle',
        })
    } finally {
        authStore.setLoading(false)
    }
}

const sessionExpired = computed(() =>
    ['session_expired', 'session_expired_no_refresh', 'refresh_failed', 'refresh_token_invalid', 'session_issue', 'invalid_refresh_token'].some(
        (key) => route.query[key] !== undefined
    )
)

onMounted(() => {
    if (route.query.password_reset_success === 'true') {
        toast.add({
            title: 'Password Reset!',
            description: 'Your password was successfully changed. You can now log in.',
            color: 'success',
        })
    }
    if (route.query.verified === 'true') {
        toast.add({
            title: 'Email Verified!',
            description: 'Your email address was successfully verified. You can now log in.',
            color: 'success',
        })
    }
    if (route.query.verification_sent === 'true') {
        toast.add({
            title: 'Verification Sent!',
            description: 'A new verification email has been sent. Check your inbox.',
            color: 'primary',
        })
    }
})
</script>
  
