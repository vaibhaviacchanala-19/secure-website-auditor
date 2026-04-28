const axios = require('axios');
const axiosRetry = require('axios-retry').default;

const apiClient = axios.create({
  timeout: 10000,
});

axiosRetry(apiClient, { 
  retries: 3, 
  retryDelay: axiosRetry.exponentialDelay,
  retryCondition: (error) => {
    return axiosRetry.isNetworkOrIdempotentRequestError(error) || error.code === 'ECONNABORTED';
  }
});

module.exports = apiClient;
