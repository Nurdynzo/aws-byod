import axios from "axios";

const useRequest = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
  timeout: 30000,
});

export {useRequest}