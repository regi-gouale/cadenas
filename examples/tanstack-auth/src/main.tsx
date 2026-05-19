import React, { useMemo, useState } from "react";
import ReactDOM from "react-dom/client";
import { useForm } from "@tanstack/react-form";
import {
  QueryClient,
  QueryClientProvider,
  queryOptions,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Outlet,
  RouterProvider,
  createRootRouteWithContext,
  createRoute,
  createRouter,
  redirect,
  useNavigate,
} from "@tanstack/react-router";
import "./styles.css";

type User = {
  id: string;
  email: string;
  email_verified: boolean;
  name: string | null;
  image: string | null;
};

type Note = {
  id: string;
  content: string;
  created_at: string;
};

type ApiErrorBody = {
  error: string;
  message: string;
};

type TotpChallengeResponse = {
  totp_required: true;
  challenge_token: string;
  user_id: string;
};

class HttpError extends Error {
  status: number;
  body: ApiErrorBody | null;

  constructor(status: number, body: ApiErrorBody | null) {
    super(body?.message ?? `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

async function parseError(res: Response): Promise<HttpError> {
  let body: ApiErrorBody | null = null;
  try {
    body = (await res.json()) as ApiErrorBody;
  } catch {
    body = null;
  }
  return new HttpError(res.status, body);
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });

  if (!res.ok) {
    throw await parseError(res);
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return (await res.json()) as T;
}

function formatNoteDate(raw: string): string {
  const direct = new Date(raw);
  if (!Number.isNaN(direct.getTime())) {
    return direct.toLocaleString("fr-FR");
  }

  // Legacy server format from time::OffsetDateTime::to_string():
  // 2026-05-19 12:34:56.123456 +00:00:00
  const normalized = raw
    .replace(" ", "T")
    .replace(/ ([+-]\d{2}:\d{2}):\d{2}$/, "$1");
  const fallback = new Date(normalized);
  if (!Number.isNaN(fallback.getTime())) {
    return fallback.toLocaleString("fr-FR");
  }

  return raw;
}

const sessionQuery = queryOptions({
  queryKey: ["session"],
  queryFn: () => api<User>("/api/auth/session"),
  retry: false,
});

function RootLayout() {
  return (
    <div className="page-shell">
      <header className="app-header">
        <h1>rauth + TanStack</h1>
        <p>Exemple React avec TanStack Router et TanStack Query</p>
      </header>
      <main className="content-wrap">
        <Outlet />
      </main>
    </div>
  );
}

function LoginPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [formError, setFormError] = useState<string | null>(null);
  const [pendingChallenge, setPendingChallenge] = useState<string | null>(null);

  const signUp = useMutation({
    mutationFn: (payload: { name: string; email: string; password: string }) =>
      api<User>("/api/auth/sign-up/email", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      setFormError(null);
      setMode("signin");
    },
    onError: (err) => {
      setFormError(err instanceof Error ? err.message : "Erreur inconnue");
    },
  });

  const signIn = useMutation({
    mutationFn: async (payload: { email: string; password: string }) => {
      const res = await fetch("/api/auth/sign-in/email", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (res.status === 202) {
        return {
          kind: "totp" as const,
          data: (await res.json()) as TotpChallengeResponse,
        };
      }

      if (!res.ok) {
        throw await parseError(res);
      }

      return { kind: "ok" as const };
    },
    onSuccess: async (result) => {
      setFormError(null);
      if (result.kind === "totp") {
        setPendingChallenge(result.data.challenge_token);
        return;
      }

      await queryClient.invalidateQueries({ queryKey: ["session"] });
      await navigate({ to: "/" });
    },
    onError: (err) => {
      setFormError(err instanceof Error ? err.message : "Erreur inconnue");
    },
  });

  const verifyTotp = useMutation({
    mutationFn: (payload: { challenge_token: string; code: string }) =>
      api("/api/auth/totp/challenge", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    onSuccess: async () => {
      setFormError(null);
      setPendingChallenge(null);
      await queryClient.invalidateQueries({ queryKey: ["session"] });
      await navigate({ to: "/" });
    },
    onError: (err) => {
      setFormError(err instanceof Error ? err.message : "Erreur inconnue");
    },
  });

  const isLoading =
    signUp.isPending || signIn.isPending || verifyTotp.isPending;

  const signInForm = useForm({
    defaultValues: {
      email: "",
      password: "",
    },
    onSubmit: async ({ value }) => {
      setFormError(null);
      await signIn.mutateAsync({
        email: value.email,
        password: value.password,
      });
    },
  });

  const signUpForm = useForm({
    defaultValues: {
      name: "",
      email: "",
      password: "",
    },
    onSubmit: async ({ value }) => {
      setFormError(null);
      await signUp.mutateAsync({
        name: value.name,
        email: value.email,
        password: value.password,
      });
    },
  });

  const totpForm = useForm({
    defaultValues: {
      code: "",
    },
    onSubmit: async ({ value }) => {
      setFormError(null);
      if (!pendingChallenge) {
        setFormError("Challenge TOTP manquant");
        return;
      }
      await verifyTotp.mutateAsync({
        challenge_token: pendingChallenge,
        code: value.code,
      });
    },
  });

  return (
    <section className="card auth-card">
      <div className="tabs">
        <button
          className={mode === "signin" ? "is-active" : ""}
          type="button"
          onClick={() => {
            setMode("signin");
            setPendingChallenge(null);
            setFormError(null);
          }}>
          Se connecter
        </button>
        <button
          className={mode === "signup" ? "is-active" : ""}
          type="button"
          onClick={() => {
            setMode("signup");
            setPendingChallenge(null);
            setFormError(null);
          }}>
          Créer un compte
        </button>
      </div>

      {pendingChallenge ? (
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            void totpForm.handleSubmit();
          }}>
          <p className="muted">
            Deuxième facteur requis. Entre le code de ton application
            d&apos;authentification.
          </p>
          <label htmlFor="totp-code">Code TOTP</label>
          <totpForm.Field
            name="code"
            validators={{
              onSubmit: ({ value }) =>
                /^\d{6}$/.test(value) ? undefined : "Code TOTP invalide",
            }}>
            {(field) => (
              <>
                <input
                  id="totp-code"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  required
                />
                {field.state.meta.errors[0] ? (
                  <p className="error-line">{field.state.meta.errors[0]}</p>
                ) : null}
              </>
            )}
          </totpForm.Field>
          <button type="submit" disabled={isLoading}>
            Vérifier
          </button>
        </form>
      ) : mode === "signin" ? (
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            void signInForm.handleSubmit();
          }}>
          <label htmlFor="signin-email">Email</label>
          <signInForm.Field
            name="email"
            validators={{
              onSubmit: ({ value }) =>
                value.includes("@") ? undefined : "Email invalide",
            }}>
            {(field) => (
              <>
                <input
                  id="signin-email"
                  type="email"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  required
                />
                {field.state.meta.errors[0] ? (
                  <p className="error-line">{field.state.meta.errors[0]}</p>
                ) : null}
              </>
            )}
          </signInForm.Field>
          <label htmlFor="signin-password">Mot de passe</label>
          <signInForm.Field
            name="password"
            validators={{
              onSubmit: ({ value }) =>
                value.length >= 8
                  ? undefined
                  : "Le mot de passe doit faire au moins 8 caractères",
            }}>
            {(field) => (
              <>
                <input
                  id="signin-password"
                  type="password"
                  autoComplete="current-password"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  required
                />
                {field.state.meta.errors[0] ? (
                  <p className="error-line">{field.state.meta.errors[0]}</p>
                ) : null}
              </>
            )}
          </signInForm.Field>
          <button type="submit" disabled={isLoading}>
            Connexion
          </button>
        </form>
      ) : (
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            event.stopPropagation();
            void signUpForm.handleSubmit();
          }}>
          <label htmlFor="signup-name">Nom</label>
          <signUpForm.Field name="name">
            {(field) => (
              <input
                id="signup-name"
                type="text"
                value={field.state.value}
                onBlur={field.handleBlur}
                onChange={(event) => field.handleChange(event.target.value)}
              />
            )}
          </signUpForm.Field>
          <label htmlFor="signup-email">Email</label>
          <signUpForm.Field
            name="email"
            validators={{
              onSubmit: ({ value }) =>
                value.includes("@") ? undefined : "Email invalide",
            }}>
            {(field) => (
              <>
                <input
                  id="signup-email"
                  type="email"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  required
                />
                {field.state.meta.errors[0] ? (
                  <p className="error-line">{field.state.meta.errors[0]}</p>
                ) : null}
              </>
            )}
          </signUpForm.Field>
          <label htmlFor="signup-password">Mot de passe</label>
          <signUpForm.Field
            name="password"
            validators={{
              onSubmit: ({ value }) =>
                value.length >= 8
                  ? undefined
                  : "Le mot de passe doit faire au moins 8 caractères",
            }}>
            {(field) => (
              <>
                <input
                  id="signup-password"
                  type="password"
                  minLength={8}
                  autoComplete="new-password"
                  value={field.state.value}
                  onBlur={field.handleBlur}
                  onChange={(event) => field.handleChange(event.target.value)}
                  required
                />
                {field.state.meta.errors[0] ? (
                  <p className="error-line">{field.state.meta.errors[0]}</p>
                ) : null}
              </>
            )}
          </signUpForm.Field>
          <button type="submit" disabled={isLoading}>
            Inscription
          </button>
        </form>
      )}

      <p className="error-line">{formError}</p>
    </section>
  );
}

function DashboardPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [noteContent, setNoteContent] = useState("");
  const [noteError, setNoteError] = useState<string | null>(null);

  const session = useQuery(sessionQuery);
  const notesQuery = useQuery({
    queryKey: ["notes"],
    queryFn: () => api<Note[]>("/api/notes"),
    staleTime: 5_000,
  });

  const signOut = useMutation({
    mutationFn: () => api("/api/auth/sign-out", { method: "POST" }),
    onSuccess: async () => {
      await queryClient.removeQueries({ queryKey: ["session"] });
      await queryClient.removeQueries({ queryKey: ["notes"] });
      await navigate({ to: "/login" });
    },
  });

  const addNote = useMutation({
    mutationFn: (payload: { content: string }) =>
      api<Note>("/api/notes", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    onSuccess: async () => {
      setNoteError(null);
      setNoteContent("");
      await queryClient.invalidateQueries({ queryKey: ["notes"] });
    },
    onError: (err) => {
      setNoteError(err instanceof Error ? err.message : "Erreur inconnue");
    },
  });

  const deleteNote = useMutation({
    mutationFn: (id: string) => api(`/api/notes/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["notes"] });
    },
  });

  const notes = useMemo(() => notesQuery.data ?? [], [notesQuery.data]);

  const onAddNote = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const content = noteContent.trim();
    if (!content) {
      setNoteError("Le contenu de la note est requis");
      return;
    }
    setNoteError(null);
    await addNote.mutateAsync({ content });
  };

  return (
    <div className="dashboard-grid">
      <section className="card">
        <h2>Session</h2>
        <p className="muted">
          Connecté en tant que <strong>{session.data?.email}</strong>
        </p>
        <button
          type="button"
          className="ghost"
          disabled={signOut.isPending}
          onClick={() => signOut.mutate()}>
          Déconnexion
        </button>
      </section>

      <section className="card">
        <h2>Notes</h2>
        <form className="row" onSubmit={onAddNote}>
          <input
            className="grow"
            placeholder="Nouvelle note..."
            value={noteContent}
            onChange={(event) => setNoteContent(event.target.value)}
            required
          />
          <button type="submit" disabled={addNote.isPending}>
            Ajouter
          </button>
        </form>
        <p className="error-line">{noteError}</p>

        {notesQuery.isLoading ? <p className="muted">Chargement...</p> : null}

        <ul className="notes-list">
          {notes.map((note) => (
            <li key={note.id}>
              <div>
                <p>{note.content}</p>
                <small>{formatNoteDate(note.created_at)}</small>
              </div>
              <button
                type="button"
                className="danger"
                disabled={deleteNote.isPending}
                onClick={() => deleteNote.mutate(note.id)}>
                Supprimer
              </button>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

const rootRoute = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: RootLayout,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: LoginPage,
  beforeLoad: async ({ context }) => {
    try {
      await context.queryClient.ensureQueryData(sessionQuery);
      throw redirect({ to: "/" });
    } catch {
      return;
    }
  },
});

const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: DashboardPage,
  beforeLoad: async ({ context }) => {
    try {
      await context.queryClient.ensureQueryData(sessionQuery);
    } catch {
      throw redirect({ to: "/login" });
    }
  },
});

const routeTree = rootRoute.addChildren([dashboardRoute, loginRoute]);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      refetchOnWindowFocus: false,
    },
  },
});

const router = createRouter({
  routeTree,
  context: {
    queryClient,
  },
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </React.StrictMode>,
);
