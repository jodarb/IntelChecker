import Layout from '@/components/Layout'
import ConnectorsPanel from '@/components/admin/ConnectorsPanel'
import { useI18n } from '@/i18n/useI18n'
import BackButton from '@/components/BackButton'

/** API keys and MISP instances (admins only — the route is guarded in App.tsx, the API in the backend). */
export default function ConnectorsPage() {
  const { t } = useI18n()
  return (
    <Layout>
      <main className="flex-1 px-6 py-6 w-full max-w-4xl mx-auto flex flex-col gap-6">
        <div className="flex items-start gap-4">
          <BackButton />
          <div>
            <h2 className="text-xl font-semibold text-foreground">{t('connectors.title')}</h2>
            <p className="text-sm text-muted-foreground mt-1">{t('connectors.pageSubtitle')}</p>
          </div>
        </div>
        <ConnectorsPanel />
      </main>
    </Layout>
  )
}
