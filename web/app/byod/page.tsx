"use client";
// src/pages/index.tsx
import React, { useState } from "react";
import { useRequest } from "@/lib/api/axios";
import {
  Box,
  Button,
  TextField,
  Typography,
  Paper,
  Container,
  CircularProgress,
  Alert,
  Stepper,
  Step,
  StepLabel,
} from "@mui/material";

const steps = ["Register Domain", "Validate DNS Records", "Complete Setup"];

interface DomainState {
  domainName: string;
  status: string;
  message?: string;
  loading: boolean;
  error?: string;
  name?: string;
  CNAME?: string;
  value?: string;
  alb_dns?: string;
  A_status?: string;
  CNAME_status?: string;
}

export default function Home() {
  const [activeStep, setActiveStep] = useState(0);
  const [domain, setDomain] = useState<DomainState>({
    domainName: "",
    status: "",
    loading: false,
  });

  const handleDomainChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setDomain({ ...domain, domainName: e.target.value });
  };

  const registerDomain = async () => {
    if (!domain.domainName) {
      setDomain({ ...domain, error: "Please enter a domain name" });
      return;
    }

    setDomain({
      ...domain,
      loading: true,
      error: undefined,
    });

    try {
      const response = await useRequest.post(
        `/register-domain`,
        { domain_name: domain.domainName },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      const data = await response.data;
      if (response.status === 201) {
        console.log(response.status);
        setDomain({
          ...domain,
          loading: false,
          status: data.status,
          message: data.message,
        });

        // if (data.status !== 'pending' && data.status !== 'error') {
        //   // If registration was successful and not a domain that already exists
        //   setActiveStep(1);
        //   validateDomain();
        // }
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      if (err.status === 409) {
        console.log(err.response.data.message);
        setDomain({
          ...domain,
          loading: false,
          status: err.response.data.status,
          message: err.response.data.message,
        });
      } else {
        setDomain({
          ...domain,
          loading: false,
          error: err.response.data.message || "Failed to register domain",
        });
      }
    }
  };

  const validateDomain = async () => {
    setActiveStep(1);
    setDomain({
      ...domain,
      loading: true,
      error: undefined,
    });

    try {
      const response = await useRequest.post(
        `/validate`,
        { domain_name: domain.domainName },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      const data = await response.data;
      if (response.status === 201) {
        console.log(response.status);
        setDomain({
          ...domain,
          loading: false,
          status: data.status,
          message: data.message,
          name: data.name,
          CNAME: data.CNAME,
          value: data.value,
          alb_dns: data.alb_dns,
        });
      } else {
        setDomain({
          ...domain,
          loading: false,
          error: data.error || "Failed to validate domain",
        });
      }
    } catch {
      setDomain({
        ...domain,
        loading: false,
        error: "Network error. Please try again.",
      });
    }
  };

  const checkDnsStatus = async () => {
    setDomain({
      ...domain,
      loading: true,
      error: undefined,
    });

    try {
      const response = await useRequest.post(
        `/check-status`,
        { domain_name: domain.domainName },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      const data = await response.data;
      if (response.status === 201) {
        console.log(response.status);
        setDomain({
          ...domain,
          loading: false,
          status: data.status,
          A_status: data.A_status,
          CNAME_status: data.CNAME_status,
        });
      }
    } catch {
      setDomain({
        ...domain,
        loading: false,
        error: "Network error. Please try again.",
      });
    }
  };

  const completeSetup = async () => {
    setDomain({
      ...domain,
      loading: true,
      error: undefined,
    });

    try {
      const response = await useRequest.post(
        `/update-alb`,
        { domain_name: domain.domainName },
        {
          headers: {
            "Content-Type": "application/json",
          },
        }
      );
      const data = await response.data;
      if (response.status === 201) {
        console.log(response.status);
        setDomain({
          ...domain,
          loading: false,
          status: "completed",
          message: "Domain setup completed successfully!",
        });
      } else {
        setDomain({
          ...domain,
          loading: false,
          error: data.error || "Failed to complete setup",
        });
      }
    } catch {
      setDomain({
        ...domain,
        loading: false,
        error: "Network error. Please try again.",
      });
    }
  };

  const renderStepContent = () => {
    switch (activeStep) {
      case 0:
        return (
          <Box mt={3}>
            <Typography variant="h6" gutterBottom>
              Enter your domain name
            </Typography>
            <TextField
              fullWidth
              label="Domain Name"
              placeholder="example.com"
              variant="outlined"
              value={domain.domainName}
              onChange={handleDomainChange}
              margin="normal"
            />
            <Box mt={2}>
              <Button
                variant="contained"
                color="primary"
                onClick={registerDomain}
                disabled={domain.loading}
              >
                {domain.loading ? (
                  <CircularProgress size={24} />
                ) : (
                  "Register Domain"
                )}
              </Button>
            </Box>
            {domain.message && (
              <Alert severity="info" sx={{ mt: 2 }}>
                {domain.message}
              </Alert>
            )}
            {domain.error && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {domain.error}
              </Alert>
            )}
            {domain.status === "PENDING_VALIDATION" && (
              <Box mt={2}>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={validateDomain}
                  // onClick={() => setActiveStep(1)}
                >
                  Proceed to Validation
                </Button>
              </Box>
            )}
          </Box>
        );
      case 1:
        return (
          <Box mt={3}>
            <Typography variant="h6" gutterBottom>
              Configure your DNS records
            </Typography>
            <Paper sx={{ p: 2, mt: 2 }}>
              <Typography variant="subtitle1" gutterBottom>
                Please add the following DNS records to your domain:
              </Typography>

              <Box sx={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr>
                      <th
                        style={{
                          border: "1px solid #ddd",
                          padding: "8px",
                          textAlign: "left",
                        }}
                      >
                        Record Type
                      </th>
                      <th
                        style={{
                          border: "1px solid #ddd",
                          padding: "8px",
                          textAlign: "left",
                        }}
                      >
                        Name
                      </th>
                      <th
                        style={{
                          border: "1px solid #ddd",
                          padding: "8px",
                          textAlign: "left",
                        }}
                      >
                        Value
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td style={{ border: "1px solid #ddd", padding: "8px" }}>
                        A
                      </td>
                      <td style={{ border: "1px solid #ddd", padding: "8px" }}>
                        {domain.domainName}
                      </td>
                      <td style={{ border: "1px solid #ddd", padding: "8px" }}>
                        {domain.alb_dns}
                      </td>
                    </tr>
                    <tr>
                      <td style={{ border: "1px solid #ddd", padding: "8px" }}>
                        {domain.CNAME}
                      </td>
                      <td style={{ border: "1px solid #ddd", padding: "8px" }}>
                        {domain.name}
                      </td>
                      <td style={{ border: "1px solid #ddd", padding: "8px" }}>
                        {domain.value}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </Box>

              <Typography variant="body2" sx={{ mt: 2 }}>
                Note: DNS propagation can take up to 48 hours to complete.
              </Typography>

              <Box mt={2}>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={checkDnsStatus}
                  disabled={domain.loading}
                >
                  {domain.loading ? (
                    <CircularProgress size={24} />
                  ) : (
                    "Check DNS Status"
                  )}
                </Button>
              </Box>
            </Paper>

            {domain.CNAME_status === "PENDING_VALIDATION" && (
              <Alert severity="error" sx={{ mt: 2 }}>
                CNAME: {domain.CNAME_status}
                {/* {domain.A_status} */}
              </Alert>
            )}

            {domain.CNAME_status === "ISSUED" && (
              <Alert severity="info" sx={{ mt: 2 }}>
                CNAME: {domain.CNAME_status}
                {/* {domain.A_status} */}
              </Alert>
            )}

            {domain.A_status === "pending" && (
              <Alert severity="error" sx={{ mt: 2 }}>
                A Record: {domain.A_status}
                {/* {domain.A_status} */}
              </Alert>
            )}

            {domain.A_status === "done" && (
              <Alert severity="info" sx={{ mt: 2 }}>
                A Record: {domain.A_status}
                {/* {domain.A_status} */}
              </Alert>
            )}
            {domain.status === "ISSUED" && (
              <Box mt={2}>
                <Button
                  variant="contained"
                  color="secondary"
                  // onClick={validateDomain}
                  onClick={() => setActiveStep(2)}
                >
                  Proceed to Completion
                </Button>
              </Box>
            )}
          </Box>
        );
      case 2:
        return (
          <Box mt={3}>
            <Typography variant="h6" gutterBottom>
              Complete Domain Setup
            </Typography>
            <Paper sx={{ p: 2, mt: 2 }}>
              <Typography variant="body1" gutterBottom>
                All DNS records have been validated. You can now complete the
                setup process.
              </Typography>

              <Box mt={2}>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={completeSetup}
                  disabled={domain.loading || domain.status === "completed"}
                >
                  {domain.loading ? (
                    <CircularProgress size={24} />
                  ) : domain.status === "completed" ? (
                    "Setup Complete"
                  ) : (
                    "Complete Setup"
                  )}
                </Button>
              </Box>

              {domain.status === "completed" && (
                <Alert severity="success" sx={{ mt: 2 }}>
                  Your domain has been successfully configured! You can now
                  access your application at {domain.domainName}.
                </Alert>
              )}
            </Paper>

            {domain.error && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {domain.error}
              </Alert>
            )}
          </Box>
        );
      default:
        return null;
    }
  };

  return (
    <Container maxWidth="lg">
      <Box sx={{ mt: 4, mb: 8 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Domain Registration
        </Typography>

        <Stepper activeStep={activeStep} sx={{ mt: 3, mb: 4 }}>
          {steps.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {renderStepContent()}
      </Box>
    </Container>
  );
}
