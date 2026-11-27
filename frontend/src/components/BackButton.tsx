import { ArrowLeft } from 'lucide-react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n/useI18n'

/**
 * The "← Back" button every view has (except the three search pages and sign-in),
 * always first, left of the title. It goes back to the previous screen of the app;
 * when the page was opened directly (a shared link, a reload in a new tab) there is
 * no such screen, so it goes to `fallback`, the view's parent.
 */
export default function BackButton({ fallback = '/' }: { fallback?: string }) {
  const { t } = useI18n()
  const navigate = useNavigate()
  // React Router marks the first page of the session with the key "default".
  const cameFromApp = useLocation().key !== 'default'
  return (
    <Button variant="ghost" size="sm" asChild className="mt-0.5 shrink-0">
      <Link to={fallback} onClick={e => {
        if (cameFromApp && !e.metaKey && !e.ctrlKey && !e.shiftKey) { e.preventDefault(); navigate(-1) }
      }}>
        <ArrowLeft className="h-4 w-4 mr-1" /> {t('common.back')}
      </Link>
    </Button>
  )
}
