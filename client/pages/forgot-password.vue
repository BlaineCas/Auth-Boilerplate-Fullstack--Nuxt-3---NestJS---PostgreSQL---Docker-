<template>
  <UCard class="w-full max-w-md mt-16 mx-auto" >
    <div class="flex flex-col items-center justify-center gap-4 p-4">
      <UAuthForm class="max-w-md mx-auto" title="Boilerplate" description="Forgot password" icon="i-tabler-alien"
        :fields="fields" :schema="schema" :submit-button="{ label: 'Reset Password', color: 'primary', block: true }"
        @submit="handleSubmit">
        <template #footer>
          <div class="text-sm text-center space-y-2">
            <p class="text-gray-400">
              Do you remember your password?
              <NuxtLink to="/login" class="font-medium text-primary-400 hover:text-primary-300 transition-colors">
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

useHead({ title: 'Forgot Password' });
definePageMeta({ layout: 'default' });

const authStore = useAuthStore();
const toast = useToast();

const schema = z.object({
  email: z.string().email('Invalid email address.'),
});

type Schema = z.output<typeof schema>;

const fields = [{
  name: 'email',
  type: 'text' as const,
  label: 'Email',
  placeholder: 'Enter your email',
  required: true
}]

const handleSubmit = async (payload: FormSubmitEvent<Schema>) => {
  if (authStore.isLoading) return;
  authStore.setLoading(true);
  try {
    await $apiFetch('/auth/forgot-password', {
      method: 'POST',
      body: payload.data.email,
    });
    toast.add({
      title: 'Check Your Email',
      description: 'If an account with this address exists, you will receive an email with instructions to reset your password. Also check your Spam folder.',
      color: 'success',
      icon: 'i-heroicons-envelope-open',
      duration: 10000
    });
  } catch (error: any) {
    console.error('Forgot password error:', error.data);
    toast.add({
      title: 'Error',
      description: error.data?.message || 'An error occurred. Please try again or check the email address.',
      color: 'error',
      icon: 'i-heroicons-exclamation-circle',
      duration: 5000,
    });
  } finally {
    authStore.setLoading(false);
  }
};
</script>
