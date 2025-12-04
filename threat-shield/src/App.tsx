import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, useLocation } from "react-router-dom";
import { AssessmentProvider } from "./context/AssessmentContext";
import { AuthProvider } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";

import Navbar from "./components/common/Navbar";
import Home from "./pages/Home";
import ThreatModel from "./pages/ThreatModel";
import ViewThreatModel from "./pages/ViewThreatModel";
import Dread from "./pages/Dread";
import Mitigation from "./pages/Mitigation";
import AttackTree from "./pages/AttackTree";
import Chat from "./pages/Chat";
import Report from "./pages/Report";
import ReportList from "./pages/ReportList";
import ThreatModelList from "./pages/ThreatModelList";
import Analytics from "./pages/Analytics";
import Settings from "./pages/Settings";
import About from "./pages/About";
import Login from "./pages/Login";
import DesignObjectives from "./pages/DesignObjectives";


// Wrapper component to conditionally show navbar
const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const location = useLocation();
  const [showNavbar, setShowNavbar] = useState(false);

  useEffect(() => {
    // Hide navbar on the login page, show it everywhere else
    const isLoginRoute = location.pathname === "/login";
    setShowNavbar(!isLoginRoute);
  }, [location]);

  return (
    <div className="min-h-screen bg-background">
      {showNavbar && <Navbar />}
      <main className={showNavbar ? "ml-64 transition-all duration-300" : ""}>
        {children}
      </main>
    </div>
  );
};

const App: React.FC = () => {
  return (
    <Router>
      <AuthProvider>
        <AssessmentProvider>
          <AppLayout>
            <Routes>
              {/* Public route */}
              <Route path="/login" element={<Login />} />

              {/* Protected routes */}
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <Home />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/home"
                element={
                  <ProtectedRoute>
                    <Home />
                  </ProtectedRoute>
                }
              />

              {/* Generation routes */}
              <Route
                path="/threat-model/:assessment_id"
                element={
                  <ProtectedRoute>
                    <ThreatModel />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/dread/:assessment_id"
                element={
                  <ProtectedRoute>
                    <Dread />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/mitigation/:assessment_id"
                element={
                  <ProtectedRoute>
                    <Mitigation />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/attack-tree/:assessment_id"
                element={
                  <ProtectedRoute>
                    <AttackTree />
                  </ProtectedRoute>
                }
              />

              {/* View-only routes */}
              <Route
                path="/view-threat-model/:assessment_id"
                element={
                  <ProtectedRoute>
                    <ViewThreatModel />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/view-dread/:assessment_id"
                element={
                  <ProtectedRoute>
                    <Dread />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/view-mitigation/:assessment_id"
                element={
                  <ProtectedRoute>
                    <Mitigation />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/view-attack-tree/:assessment_id"
                element={
                  <ProtectedRoute>
                    <AttackTree />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/chat/:assessment_id"
                element={
                  <ProtectedRoute>
                    <Chat />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/report/:assessment_id"
                element={
                  <ProtectedRoute>
                    <Report />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/chat"
                element={
                  <ProtectedRoute>
                    <Chat />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/report"
                element={
                  <ProtectedRoute>
                    <Report />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/reports"
                element={
                  <ProtectedRoute>
                    <ReportList />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/threat-models"
                element={
                  <ProtectedRoute>
                    <ThreatModelList />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/analytics"
                element={
                  <ProtectedRoute>
                    <Analytics />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/settings"
                element={
                  <ProtectedRoute>
                    <Settings />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/about"
                element={
                  <ProtectedRoute>
                    <About />
                  </ProtectedRoute>
                }
              />
              <Route
              path="/design-objectives"
              element={
                <ProtectedRoute>
                    <DesignObjectives />
                </ProtectedRoute>
              }
              />
            </Routes> 
          </AppLayout>
        </AssessmentProvider>
      </AuthProvider>
    </Router>
  );
};

export default App;
