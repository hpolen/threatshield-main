// pages/DesignObjectives.tsx

import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { API_BASE_URL, apiService } from "../services/api";

type DesignObjectiveKey =
  | "maintainability"
  | "availability"
  | "scale"
  | "secure"
  | "dataIntegrity"
  | "systemIntegration";

interface DesignObjectiveConfig {
  key: DesignObjectiveKey;
  label: string;
  description: string;
}

const DESIGN_OBJECTIVES: DesignObjectiveConfig[] = [
  {
    key: "maintainability",
    label: "Maintainability",
    description:
      "How easy it is to change, test, and operate the system over time.",
  },
  {
    key: "availability",
    label: "Availability",
    description:
      "Resilience to failures, uptime targets, and graceful degradation.",
  },
  {
    key: "scale",
    label: "Scale",
    description:
      "Ability to handle growth in users, data, and transaction volume.",
  },
  {
    key: "secure",
    label: "Secure",
    description: "Protection against threats, misuse, and data compromise.",
  },
  {
    key: "dataIntegrity",
    label: "Data Integrity",
    description:
      "Correctness, consistency, and lineage of data across systems.",
  },
  {
    key: "systemIntegration",
    label: "System Integration",
    description:
      "Quality of interfaces, upstream/downstream dependencies, and coupling.",
  },
];

type Importance = "low" | "medium" | "high" | "n/a";

interface ObjectiveState {
  importance: Importance;
  // kept for presets/backwards compatibility, not edited in UI
  successCriteria: string;
  currentState: string;
}

type ObjectiveFormState = Record<DesignObjectiveKey, ObjectiveState>;

// ---- Result types based on backend JSON shape ----

interface DesignObjectiveResult {
  name: string;
  rating: string;
  score: number;
  justification: string;
  risks: string[];
  recommendations: string[];
  evidence: string;
}

interface DesignObjectivesApiResult {
  overall_summary?: string;
  markdown?: string;
  quick_scorecard?: Record<string, string>;
  objectives?: DesignObjectiveResult[];
  raw_response?: {
    overall_summary?: string;
    quick_scorecard?: Record<string, string>;
    objectives?: DesignObjectiveResult[];
  };
}

const defaultObjectiveState: ObjectiveState = {
  importance: "medium",
  successCriteria: "",
  currentState: "",
};

const makeInitialState = (): ObjectiveFormState => ({
  maintainability: { ...defaultObjectiveState },
  availability: { ...defaultObjectiveState },
  scale: { ...defaultObjectiveState },
  secure: { ...defaultObjectiveState },
  dataIntegrity: { ...defaultObjectiveState },
  systemIntegration: { ...defaultObjectiveState },
});

// Default global “what good looks like” definitions.
// Overridden by Settings.designObjectivesGood if present.
const DEFAULT_DO_GOOD: Record<string, string> = {
  Maintainability:
    "Services and components are loosely coupled, with clear ownership, automated tests, and deployment pipelines. Changes can be made safely without ripple effects, and operational runbooks are in place.",
  Availability:
    "Critical user journeys meet agreed uptime and SLO targets. The system degrades gracefully on dependency failure, has clear RTO/RPO, and failover or rollback paths are tested regularly.",
  Scale:
    "The system scales predictably with load. Capacity bottlenecks are understood, autoscaling or capacity management is in place, and major traffic events can be handled without emergency rework.",
  Secure:
    "Security controls follow least-privilege and zero-trust principles. Authentication, authorization, encryption in transit/at rest, and secrets management are robust and regularly reviewed.",
  "Data Integrity":
    "Data is accurate, consistent, and traceable across systems. There are controls to prevent loss, duplication, or corruption, and reconciliation or lineage is in place for critical data flows.",
  "System Integration":
    "Interfaces between systems are well-defined, versioned, and resilient. Dependencies are managed via contracts or APIs rather than tight coupling, and upstream/downstream impact is understood.",
};

// ---- Presets for quick testing ----

interface DesignObjectivePreset {
  id: string;
  label: string;
  projectName: string;
  description: string;
  architectureNotes?: string;
  objectives: ObjectiveFormState;
}

const PRESETS: DesignObjectivePreset[] = [
  {
    id: "payments-platform",
    label: "Payments Microservices Platform",
    projectName: "Real-Time Payments Microservices Platform",
    description:
      "Microservices-based payments platform handling card and ACH transactions with near real-time posting, supporting multiple upstream channels (mobile, web, core banking) and downstream ledger systems.",
    architectureNotes:
      "Deployed on Kubernetes with horizontal pod autoscaling; event-driven via Kafka. Mix of Java and Node services. Legacy mainframe ledger still in the critical path for settlement.",
    objectives: {
      maintainability: {
        importance: "high",
        successCriteria:
          "Services are loosely coupled with clear domain boundaries, well-documented APIs, and automated regression tests. Teams can deploy independently multiple times per day.",
        currentState:
          "Most services have decent test coverage but domain boundaries are still fuzzy. Some shared libraries create coupling across teams and deployments require coordination.",
      },
      availability: {
        importance: "high",
        successCriteria:
          "99.99% uptime for core payment flows, with graceful degradation when dependencies fail. Clear RTO/RPO for critical components.",
        currentState:
          "We have multi-AZ deployment and circuit breakers, but our dependency on a single legacy ledger instance means outages there cause full impact.",
      },
      scale: {
        importance: "high",
        successCriteria:
          "Scales linearly with traffic peaks (e.g., month-end, promo campaigns) without major rework. Capacity planning is straightforward.",
        currentState:
          "Kubernetes HPA helps handle normal peaks, but certain services like statement generation and reporting do not scale well under high load.",
      },
      secure: {
        importance: "high",
        successCriteria:
          "End-to-end encryption, least-privilege access, strong authentication and authorization, and proper segregation of duties.",
        currentState:
          "Service-to-service auth is via mTLS, but some internal admin APIs are still exposed more broadly than they should be. Secrets management is migrating to a vault solution.",
      },
      dataIntegrity: {
        importance: "high",
        successCriteria:
          "No lost or duplicated transactions; clear reconciliation between event streams and ledger; full audit trail.",
        currentState:
          "Kafka topics are replicated and idempotency keys are used, but we rely on nightly reconciliation jobs to catch certain mismatches with the ledger.",
      },
      systemIntegration: {
        importance: "medium",
        successCriteria:
          "Stable, versioned APIs for all integrations; bulk and real-time options; low coupling to legacy systems.",
        currentState:
          "We still have point-to-point integrations to a few legacy systems, and some partner APIs are tightly coupled to internal data models.",
      },
    },
  },
  {
    id: "customer-360",
    label: "Customer 360 Data Hub",
    projectName: "Customer 360 Analytics & Profile Hub",
    description:
      "Centralized customer 360 platform that aggregates profile, interaction, and product data into a unified view for analytics, marketing, and servicing.",
    architectureNotes:
      "Lakehouse architecture on cloud data platform. Mix of batch ingestion from core systems and near real-time streams from digital channels.",
    objectives: {
      maintainability: {
        importance: "medium",
        successCriteria:
          "Pipelines are modular with clear ownership; schema evolution is manageable; changes can be deployed without lengthy regression cycles.",
        currentState:
          "Some key pipelines are still monolithic and hard to test. Ownership across domains is improving but not fully clear.",
      },
      availability: {
        importance: "medium",
        successCriteria:
          "Data SLA is met for daily and hourly refreshes; critical dashboards are available during business hours.",
        currentState:
          "Most SLAs are met, but heavy backfills can impact daily reporting and cause delays.",
      },
      scale: {
        importance: "high",
        successCriteria:
          "Can scale storage and compute independently; able to onboard new data sources without major re-architecture.",
        currentState:
          "Storage scales well but some transformation jobs are not optimized, leading to long runtimes as data volume grows.",
      },
      secure: {
        importance: "high",
        successCriteria:
          "Fine-grained access control per attribute/domain; strong masking/anonymization for PII; full audit logging.",
        currentState:
          "Role-based controls exist at dataset level but column-level masking is inconsistent; audit logging is present but not centrally monitored.",
      },
      dataIntegrity: {
        importance: "high",
        successCriteria:
          "Consistent identifiers for customers across all domains; lineage and provenance tracked end to end.",
        currentState:
          "Multiple ID schemes still exist; we rely on fuzzy matching in some areas and lineage is not always obvious.",
      },
      systemIntegration: {
        importance: "medium",
        successCriteria:
          "Clear contracts for data consumption via APIs and BI tools; semantic layer hides raw model complexity.",
        currentState:
          "Some consumers connect directly to raw tables; the semantic layer is still being rolled out.",
      },
    },
  },
  {
    id: "blank-high-risk",
    label: "Blank Template – High Risk Focus",
    projectName: "Ad hoc Assessment – High Risk Focus",
    description:
      "Quick-start template for experimenting with high-risk, partially aligned architectures to see how the engine responds.",
    architectureNotes:
      "Use this when you want the model to surface lots of risks and recommendations without filling in every field.",
    objectives: makeInitialState(),
  },
];

// Helper to color-code ratings
const ratingPillClasses = (rating: string) => {
  const normalized = rating.toLowerCase();
  if (normalized.includes("does not meet")) {
    return "bg-red-100 text-red-800 border-red-200";
  }
  if (normalized.includes("partially")) {
    return "bg-amber-100 text-amber-800 border-amber-200";
  }
  if (normalized.includes("meets") || normalized.includes("exceeds")) {
    return "bg-emerald-100 text-emerald-800 border-emerald-200";
  }
  return "bg-slate-100 text-slate-800 border-slate-200";
};

const DesignObjectives: React.FC = () => {
  const navigate = useNavigate();

  const [projectName, setProjectName] = useState("");
  const [description, setDescription] = useState("");
  const [architectureNotes, setArchitectureNotes] = useState("");
  const [objectives, setObjectives] = useState<ObjectiveFormState>(
    makeInitialState()
  );
  const [selectedFiles, setSelectedFiles] = useState<FileList | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [apiResult, setApiResult] = useState<DesignObjectivesApiResult | null>(
    null
  );
  const [showRawJson, setShowRawJson] = useState(false);
  const [selectedPresetId, setSelectedPresetId] = useState<string>("");

  // Global “what good looks like” definitions loaded from Settings.
  // Used only in the payload / evaluation, not shown in the UI.
  const [doDefinitions, setDoDefinitions] = useState<Record<string, string>>(
    () => ({ ...DEFAULT_DO_GOOD })
  );

  // Load settings to override DEFAULT_DO_GOOD with org-specific definitions
  useEffect(() => {
    const loadSettings = async () => {
      try {
        const response = await apiService.getSettings();
        if (response && response.data) {
          const data = response.data as {
            designObjectivesGood?: Record<string, string>;
          };
          if (data.designObjectivesGood) {
            setDoDefinitions((prev) => ({
              ...prev,
              ...data.designObjectivesGood,
            }));
          }
        }
      } catch (error) {
        console.error("Error loading design objective definitions:", error);
        // On error, we just fall back to DEFAULT_DO_GOOD – no hard failure.
      }
    };

    loadSettings();
  }, []);

  const handleObjectiveChange = (
    key: DesignObjectiveKey,
    field: keyof ObjectiveState,
    value: string
  ) => {
    setObjectives((prev) => ({
      ...prev,
      [key]: {
        ...prev[key],
        [field]: field === "importance" ? (value as Importance) : value,
      },
    }));
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSelectedFiles(e.target.files);
  };

  const handlePresetChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const presetId = e.target.value;
    setSelectedPresetId(presetId);

    if (!presetId) return;

    const preset = PRESETS.find((p) => p.id === presetId);
    if (!preset) return;

    setProjectName(preset.projectName);
    setDescription(preset.description);
    setArchitectureNotes(preset.architectureNotes ?? "");
    setObjectives(preset.objectives);
    setApiError(null);
    setApiResult(null);
    setShowRawJson(false);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setApiError(null);
    setApiResult(null);
    setIsSubmitting(true);

    try {
      if (!projectName.trim() || !description.trim()) {
        throw new Error(
          "Please provide a project name and high-level description."
        );
      }

      const artifacts =
        selectedFiles != null
          ? Array.from(selectedFiles).map((f) => f.name)
          : [];

      const assessmentIdSlug =
        projectName
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, "-")
          .replace(/(^-|-$)/g, "") || "design-objectives-adhoc";

      // Build architecture_context as a single text block for the LLM.
      const architectureLines: string[] = [
        `Project Name: ${projectName.trim()}`,
        "",
        "High-Level Description:",
        description.trim(),
      ];

      if (architectureNotes.trim()) {
        architectureLines.push(
          "",
          "Architecture Notes:",
          architectureNotes.trim()
        );
      }

      architectureLines.push("", "Design Objectives:");

      DESIGN_OBJECTIVES.forEach((cfg) => {
        const state = objectives[cfg.key];
        const goodDefinition =
          doDefinitions[cfg.label] ?? DEFAULT_DO_GOOD[cfg.label] ?? "n/a";

        architectureLines.push(
          "",
          `${cfg.label} (importance: ${state.importance})`,
          `Target / success criteria (org-wide): ${goodDefinition}`,
          `Current behaviour: ${state.currentState || "n/a"}`
        );
      });

      const architectureContext = architectureLines.join("\n");

      // Map objectives into a server-friendly structure keyed by label.
      const objectivesPayload: Record<
        string,
        {
          importance: Importance;
          success_criteria: string;
          current_state: string;
        }
      > = {};

      DESIGN_OBJECTIVES.forEach((cfg) => {
        const state = objectives[cfg.key];
        const goodDefinition =
          doDefinitions[cfg.label] ?? DEFAULT_DO_GOOD[cfg.label] ?? "n/a";

        objectivesPayload[cfg.label] = {
          importance: state.importance,
          success_criteria: goodDefinition,
          current_state: state.currentState,
        };
      });

      const payload = {
        assessment_id: assessmentIdSlug,
        architecture_context: architectureContext,
        objectives: objectivesPayload,
        projectName,
        description,
        architectureNotes,
        artifacts,
      };

      const response = await fetch(
        `${API_BASE_URL}/design-objectives/alignment`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }
      );

      if (!response.ok) {
        const errorData = await response.json().catch(() => null);
        throw new Error(
          errorData?.error ||
            `Failed to run design objective alignment (${response.status})`
        );
      }

      const result: DesignObjectivesApiResult = await response.json();
      setApiResult(result);
    } catch (err: any) {
      console.error("Design objective alignment failed:", err);
      setApiError(
        err?.message ||
          "Something went wrong while running the design objective alignment."
      );
    } finally {
      setIsSubmitting(false);
      setShowRawJson(false);
    }
  };

  // Normalize the backend result so we can render consistently
  const normalizedResult = useMemo(() => {
    if (!apiResult) return null;
    const base = apiResult.raw_response ?? apiResult;

    return {
      overallSummary:
        base.overall_summary ?? apiResult.overall_summary ?? "",
      quickScorecard:
        base.quick_scorecard ?? apiResult.quick_scorecard ?? {},
      objectives: (base.objectives ?? apiResult.objectives ?? []) as
        | DesignObjectiveResult[]
        | undefined,
      markdown: apiResult.markdown,
    };
  }, [apiResult]);

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Top bar / breadcrumb */}
      <div className="border-b border-slate-200 bg-white">
        <div className="mx-auto max-w-6xl px-6 py-4 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-slate-900">
              Design Objective Alignment
            </h1>
            <p className="mt-1 text-sm text-slate-500">
              Evaluate how your architecture aligns to Maintainability,
              Availability, Scale, Security, Data Integrity, and System
              Integration.
            </p>
          </div>
          <button
            type="button"
            onClick={() => navigate(-1)}
            className="rounded-lg border border-slate-200 px-3 py-1.5 text-sm text-slate-600 hover:bg-slate-50"
          >
            Back
          </button>
        </div>
      </div>

      <main className="mx-auto max-w-6xl px-6 py-8 space-y-6">
        {/* Preset selector + Project info */}
        <section className="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
            <h2 className="text-lg font-semibold text-slate-900">
              Project / Architecture Context
            </h2>
            <div className="flex items-center gap-2">
              <label className="text-xs font-medium text-slate-600">
                Load preset:
              </label>
              <select
                value={selectedPresetId}
                onChange={handlePresetChange}
                className="rounded-lg border border-slate-300 px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              >
                <option value="">None</option>
                {PRESETS.map((preset) => (
                  <option key={preset.id} value={preset.id}>
                    {preset.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="grid gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">
                Architecture / Project Name
                <span className="text-red-500">*</span>
              </label>
              <input
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="e.g., Payments Microservices Platform"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">
                High-Level Description
                <span className="text-red-500">*</span>
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Summarize the architecture, core flows, and critical components."
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">
                Architecture Notes
              </label>
              <textarea
                value={architectureNotes}
                onChange={(e) => setArchitectureNotes(e.target.value)}
                rows={3}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Call out any known constraints, tech stack details, or assumptions the AI should know."
              />
            </div>
          </div>
        </section>

        {/* Artifacts */}
        <section className="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">
          <h2 className="text-lg font-semibold text-slate-900 mb-2">
            Architecture Artifacts
          </h2>
          <p className="text-sm text-slate-500 mb-4">
            Attach architecture diagrams, sequence diagrams, or supporting docs.
            File uploads are not yet persisted – we will use names as hints for
            now.
          </p>
          <input
            type="file"
            multiple
            onChange={handleFileChange}
            className="block w-full text-sm text-slate-600
                       file:mr-3 file:rounded-md file:border-0
                       file:bg-blue-50 file:px-3 file:py-2
                       file:text-sm file:font-medium file:text-blue-700
                       hover:file:bg-blue-100"
          />
          {selectedFiles && selectedFiles.length > 0 && (
            <p className="mt-2 text-xs text-slate-500">
              Selected:{" "}
              {Array.from(selectedFiles)
                .map((f) => f.name)
                .join(", ")}
            </p>
          )}
        </section>

        {/* Design objectives form */}
        <section className="bg-white rounded-2xl shadow-sm border border-slate-200 p-6">
          <h2 className="text-lg font-semibold text-slate-900 mb-1">
            Design Objectives
          </h2>
          <p className="text-sm text-slate-500 mb-4">
            For each objective, set the importance and describe how the current
            design behaves. The engine will compare this against the
            organization-wide definition of “good” from Settings and surface
            misalignment, risks, and recommendations.
          </p>

          <div className="space-y-6">
            {DESIGN_OBJECTIVES.map((obj) => {
              const state = objectives[obj.key];

              return (
                <div
                  key={obj.key}
                  className="border border-slate-200 rounded-xl p-4 bg-slate-50/60"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
                    <div>
                      <h3 className="text-sm font-semibold text-slate-900">
                        {obj.label}
                      </h3>
                      <p className="text-xs text-slate-500 mt-1 max-w-xl">
                        {obj.description}
                      </p>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-600 mb-1">
                        Importance
                      </label>
                      <select
                        value={state.importance}
                        onChange={(e) =>
                          handleObjectiveChange(
                            obj.key,
                            "importance",
                            e.target.value
                          )
                        }
                        className="rounded-lg border border-slate-300 px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      >
                        <option value="n/a">N/A / out of scope</option>
                        <option value="low">Nice to have</option>
                        <option value="medium">Important</option>
                        <option value="high">Critical</option>
                      </select>
                    </div>
                  </div>

                  <div className="grid gap-3">
                    <div>
                      <label className="block text-xs font-medium text-slate-600 mb-1">
                        How the current design behaves today
                      </label>
                      <textarea
                        rows={3}
                        value={state.currentState}
                        onChange={(e) =>
                          handleObjectiveChange(
                            obj.key,
                            "currentState",
                            e.target.value
                          )
                        }
                        className="w-full rounded-lg border border-slate-300 px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        placeholder={`Call out current patterns, constraints, and known risks for ${obj.label.toLowerCase()}.`}
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* Run alignment + results */}
        <section className="bg-white rounded-2xl shadow-sm border border-slate-200 p-6 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-slate-900">
                Run Alignment Engine
              </h2>
              <p className="text-sm text-slate-500">
                This will call the backend Design Objective Alignment API and
                store the results alongside your architecture assessments.
              </p>
            </div>
            <button
              type="button"
              onClick={handleSubmit}
              disabled={isSubmitting}
              className="inline-flex items-center rounded-xl bg-blue-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-blue-700 disabled:opacity-60"
            >
              {isSubmitting ? "Running alignment…" : "Run Alignment"}
            </button>
          </div>

          {apiError && (
            <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {apiError}
            </div>
          )}

          {/* Pretty results */}
          {normalizedResult && (
            <div className="space-y-4">
              {/* Overall summary */}
              {normalizedResult.overallSummary && (
                <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                  <h3 className="text-sm font-semibold text-slate-900 mb-1">
                    Overall Architecture Summary
                  </h3>
                  <p className="text-sm text-slate-700">
                    {normalizedResult.overallSummary}
                  </p>
                </div>
              )}

              {/* Quick scorecard */}
              {normalizedResult.quickScorecard &&
                Object.keys(normalizedResult.quickScorecard).length > 0 && (
                  <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <h3 className="text-sm font-semibold text-slate-900 mb-2">
                      Design Objective Scorecard
                    </h3>
                    <div className="grid gap-2 md:grid-cols-3">
                      {Object.entries(normalizedResult.quickScorecard).map(
                        ([objectiveName, rating]) => (
                          <div
                            key={objectiveName}
                            className="flex items-center justify-between rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs"
                          >
                            <span className="font-medium text-slate-800">
                              {objectiveName}
                            </span>
                            <span
                              className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${ratingPillClasses(
                                rating
                              )}`}
                            >
                              {rating}
                            </span>
                          </div>
                        )
                      )}
                    </div>
                  </div>
                )}

              {/* Per-objective detail */}
              {normalizedResult.objectives &&
                normalizedResult.objectives.length > 0 && (
                  <div className="space-y-3">
                    <h3 className="text-sm font-semibold text-slate-900">
                      Detailed Objective Analysis
                    </h3>
                    {normalizedResult.objectives.map((obj) => (
                      <div
                        key={obj.name}
                        className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                          <div>
                            <h4 className="text-sm font-semibold text-slate-900">
                              {obj.name}
                            </h4>
                            <p className="text-xs text-slate-500">
                              Rating:{" "}
                              <span className="font-medium">
                                {obj.rating}
                              </span>{" "}
                              • Score:{" "}
                              <span className="font-medium">
                                {obj.score}
                              </span>
                            </p>
                          </div>
                          <span
                            className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${ratingPillClasses(
                              obj.rating
                            )}`}
                          >
                            {obj.rating}
                          </span>
                        </div>

                        <div className="space-y-2 text-xs text-slate-700">
                          <div>
                            <p className="font-semibold mb-0.5">
                              Justification
                            </p>
                            <p>{obj.justification}</p>
                          </div>

                          {obj.risks && obj.risks.length > 0 && (
                            <div>
                              <p className="font-semibold mb-0.5">Key Risks</p>
                              <ul className="list-disc list-inside space-y-0.5">
                                {obj.risks.map((risk, idx) => (
                                  <li key={idx}>{risk}</li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {obj.recommendations &&
                            obj.recommendations.length > 0 && (
                              <div>
                                <p className="font-semibold mb-0.5">
                                  Recommendations
                                </p>
                                <ul className="list-disc list-inside space-y-0.5">
                                  {obj.recommendations.map((rec, idx) => (
                                    <li key={idx}>{rec}</li>
                                  ))}
                                </ul>
                              </div>
                            )}

                          {obj.evidence && (
                            <div>
                              <p className="font-semibold mb-0.5">
                                Evidence / References
                              </p>
                              <p>{obj.evidence}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

              {/* Raw JSON toggle */}
              <div className="pt-2 border-t border-slate-100 mt-2">
                <button
                  type="button"
                  onClick={() => setShowRawJson((prev) => !prev)}
                  className="text-xs text-slate-500 hover:text-slate-700 underline"
                >
                  {showRawJson ? "Hide raw JSON" : "Show raw JSON"}
                </button>
                {showRawJson && apiResult && (
                  <div className="mt-2 rounded-lg border border-slate-200 bg-slate-900 text-slate-50 px-3 py-3 text-[11px] font-mono whitespace-pre-wrap max-h-80 overflow-auto">
                    {JSON.stringify(apiResult, null, 2)}
                  </div>
                )}
              </div>
            </div>
          )}
        </section>
      </main>
    </div>
  );
};

export default DesignObjectives;
