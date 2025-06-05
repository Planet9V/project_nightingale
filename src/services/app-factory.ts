// Application Factory Service
// Provides application-specific configurations and service instances

import { ApplicationConfig, getCurrentAppConfig, getOptimalAIProvider } from '../config/app-namespaces';
import { openRouterService } from './openrouter';
import { googleAIService } from './google-ai';
import { deepSeekService } from './deepseek';
import { jinaAIService } from './jina-ai';
import { newsAPIService } from './news-api';
import { googleScholarService } from './google-scholar';
import { tavilyService } from './tavily';
import { n8nService } from './n8n';
import { logger } from '../utils/logger';

export interface AIServiceMap {
  openrouter: typeof openRouterService;
  'google-ai': typeof googleAIService;
  deepseek: typeof deepSeekService;
  jina: typeof jinaAIService;
  news: typeof newsAPIService;
  scholar: typeof googleScholarService;
  tavily: typeof tavilyService;
}

export interface AppServiceFactory {
  config: ApplicationConfig;
  ai: {
    primary: any;
    embeddings: any;
    research: any[];
    specialized: any[];
  };
  workflows: typeof n8nService;
  features: {
    realTime: boolean;
    semanticSearch: boolean;
    automation: boolean;
    multiTenant: boolean;
  };
}

class ApplicationFactory {
  private serviceMap: AIServiceMap = {
    'openrouter': openRouterService,
    'google-ai': googleAIService,
    'deepseek': deepSeekService,
    'jina': jinaAIService,
    'news': newsAPIService,
    'scholar': googleScholarService,
    'tavily': tavilyService
  };

  private appFactories: Map<string, AppServiceFactory> = new Map();

  // Create application-specific service factory
  createAppFactory(config?: ApplicationConfig): AppServiceFactory {
    const appConfig = config || getCurrentAppConfig();
    const cacheKey = appConfig.namespace;

    // Return cached factory if exists
    if (this.appFactories.has(cacheKey)) {
      return this.appFactories.get(cacheKey)!;
    }

    // Create new factory
    const factory: AppServiceFactory = {
      config: appConfig,
      ai: {
        primary: this.getService(appConfig.aiProviders.primary),
        embeddings: this.getService(appConfig.aiProviders.embeddings),
        research: appConfig.aiProviders.research.map(provider => this.getService(provider)),
        specialized: appConfig.aiProviders.specialized.map(provider => this.getService(provider))
      },
      workflows: n8nService,
      features: {
        realTime: appConfig.features.realTimeUpdates,
        semanticSearch: appConfig.features.semanticSearch,
        automation: appConfig.features.workflowAutomation,
        multiTenant: appConfig.features.multiTenant
      }
    };

    // Cache and return
    this.appFactories.set(cacheKey, factory);
    return factory;
  }

  // Get service instance by name
  private getService(providerName: string): any {
    if (!this.serviceMap[providerName as keyof AIServiceMap]) {
      logger.warn(`Unknown service provider: ${providerName}`);
      return null;
    }
    return this.serviceMap[providerName as keyof AIServiceMap];
  }

  // Application-specific AI operations
  async generateContent(
    content: string,
    type: 'description' | 'summary' | 'analysis' | 'creative',
    appConfig?: ApplicationConfig
  ): Promise<string> {
    const factory = this.createAppFactory(appConfig);
    const primaryService = factory.ai.primary;

    try {
      if (primaryService === openRouterService) {
        const response = await openRouterService.generateCompletion({
          model: 'gpt-4-turbo',
          messages: [
            { role: 'system', content: this.getSystemPrompt(type, factory.config) },
            { role: 'user', content }
          ],
          temperature: this.getTemperatureForType(type)
        });
        return response.choices[0].message.content;
      }

      if (primaryService === googleAIService) {
        const response = await googleAIService.generateText({
          prompt: content,
          systemInstruction: this.getSystemPrompt(type, factory.config),
          temperature: this.getTemperatureForType(type)
        });
        return response.text;
      }

      if (primaryService === deepSeekService) {
        const response = await deepSeekService.generateCompletion({
          model: deepSeekService.models.DEEPSEEK_CHAT,
          messages: [
            { role: 'system', content: this.getSystemPrompt(type, factory.config) },
            { role: 'user', content }
          ],
          temperature: this.getTemperatureForType(type)
        });
        return response.choices[0].message.content;
      }

      throw new Error('No valid primary AI service configured');
    } catch (error) {
      logger.error('Primary AI service failed, attempting fallback:', error);
      return this.fallbackGeneration(content, type, factory);
    }
  }

  // Fallback generation with alternative providers
  private async fallbackGeneration(
    content: string,
    type: string,
    factory: AppServiceFactory
  ): Promise<string> {
    const fallbackOrder = ['openrouter', 'google-ai', 'deepseek'];
    
    for (const providerName of fallbackOrder) {
      try {
        const service = this.getService(providerName);
        if (!service) continue;

        if (providerName === 'google-ai') {
          const response = await googleAIService.generateText({
            prompt: content,
            systemInstruction: this.getSystemPrompt(type, factory.config)
          });
          return response.text;
        }

        // Default to OpenRouter-style API for other providers
        const response = await service.generateCompletion({
          model: service.models ? Object.values(service.models)[0] : 'default',
          messages: [
            { role: 'system', content: this.getSystemPrompt(type, factory.config) },
            { role: 'user', content }
          ]
        });
        
        return response.choices[0].message.content;
      } catch (error) {
        logger.warn(`Fallback provider ${providerName} failed:`, error);
        continue;
      }
    }

    throw new Error('All AI providers failed');
  }

  // Generate embeddings using configured provider
  async generateEmbeddings(
    text: string | string[],
    appConfig?: ApplicationConfig
  ): Promise<number[] | number[][]> {
    const factory = this.createAppFactory(appConfig);
    const embeddingsService = factory.ai.embeddings;

    try {
      if (embeddingsService === jinaAIService) {
        if (Array.isArray(text)) {
          return await jinaAIService.generateMultipleEmbeddings(text);
        } else {
          return await jinaAIService.generateVehicleEmbedding(text);
        }
      }

      // Fallback to OpenAI-style embedding generation
      const { generateEmbedding } = await import('./embeddings');
      
      if (Array.isArray(text)) {
        const embeddings = await Promise.all(
          text.map(t => generateEmbedding(t, 'document'))
        );
        return embeddings;
      } else {
        return await generateEmbedding(text, 'document');
      }
    } catch (error) {
      logger.error('Embedding generation failed:', error);
      throw error;
    }
  }

  // Research data aggregation
  async gatherResearchData(
    query: string,
    sources?: string[],
    appConfig?: ApplicationConfig
  ): Promise<any> {
    const factory = this.createAppFactory(appConfig);
    const researchSources = sources || factory.config.aiProviders.research;
    const results: any = {};

    const promises = researchSources.map(async (source) => {
      try {
        switch (source) {
          case 'news':
            results.news = await newsAPIService.searchNews({
              q: query,
              sortBy: 'relevancy',
              pageSize: 10
            });
            break;
            
          case 'scholar':
            results.research = await googleScholarService.searchScholar({
              q: query,
              num: 10
            });
            break;
            
          case 'tavily':
            results.web = await tavilyService.search({
              query,
              search_depth: 'basic',
              max_results: 10
            });
            break;
            
          default:
            logger.warn(`Unknown research source: ${source}`);
        }
      } catch (error) {
        logger.error(`Research source ${source} failed:`, error);
        results[source] = { error: error.message };
      }
    });

    await Promise.all(promises);
    return results;
  }

  // Application-specific workflow execution
  async executeWorkflow(
    workflowType: string,
    data: any,
    appConfig?: ApplicationConfig
  ): Promise<any> {
    const factory = this.createAppFactory(appConfig);
    
    if (!factory.features.automation) {
      throw new Error('Workflow automation not enabled for this application');
    }

    const workflowMap = this.getWorkflowMappings(factory.config);
    const webhookPath = workflowMap[workflowType];
    
    if (!webhookPath) {
      throw new Error(`Unknown workflow type: ${workflowType}`);
    }

    try {
      const result = await fetch(`${process.env.N8N_WEBHOOK_URL}${webhookPath}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.N8N_API_KEY}`
        },
        body: JSON.stringify({
          ...data,
          namespace: factory.config.namespace,
          application_type: process.env.APPLICATION_TYPE,
          timestamp: new Date().toISOString()
        })
      });

      return await result.json();
    } catch (error) {
      logger.error(`Workflow execution failed for ${workflowType}:`, error);
      throw error;
    }
  }

  // Get application-specific system prompts
  private getSystemPrompt(type: string, config: ApplicationConfig): string {
    const basePrompts = {
      description: 'You are an expert content writer specializing in compelling descriptions.',
      summary: 'You are an expert at creating concise, informative summaries.',
      analysis: 'You are an expert analyst providing detailed insights and recommendations.',
      creative: 'You are a creative writer with expertise in engaging content creation.'
    };

    const appSpecificContext = this.getAppContext(config);
    return `${basePrompts[type as keyof typeof basePrompts]} ${appSpecificContext}`;
  }

  // Get application-specific context
  private getAppContext(config: ApplicationConfig): string {
    const contextMap: Record<string, string> = {
      'cc_': 'You specialize in classic cars, automotive history, and collector vehicle markets.',
      're_': 'You specialize in real estate, property markets, and investment opportunities.',
      'hc_': 'You specialize in healthcare, medical research, and clinical best practices.',
      'ft_': 'You specialize in financial technology, markets, and investment strategies.',
      'ec_': 'You specialize in e-commerce, retail, and consumer behavior.',
      'ed_': 'You specialize in education, learning methodologies, and academic content.',
      'mp_': 'You specialize in marketplace dynamics, product categorization, and user experience.'
    };

    return contextMap[config.namespace] || 'You are a knowledgeable expert in your field.';
  }

  // Get workflow mappings for application
  private getWorkflowMappings(config: ApplicationConfig): Record<string, string> {
    const baseWorkflows = {
      'data_enrichment': '/webhook/enrich-data',
      'content_generation': '/webhook/generate-content',
      'analysis': '/webhook/analyze-data'
    };

    const appSpecificWorkflows: Record<string, Record<string, string>> = {
      'cc_': {
        ...baseWorkflows,
        'vehicle_valuation': '/webhook/value-vehicle',
        'market_analysis': '/webhook/analyze-car-market',
        'restoration_guide': '/webhook/restoration-advice'
      },
      're_': {
        ...baseWorkflows,
        'property_valuation': '/webhook/value-property',
        'market_trends': '/webhook/analyze-market-trends',
        'lead_scoring': '/webhook/score-leads'
      },
      'hc_': {
        ...baseWorkflows,
        'research_synthesis': '/webhook/synthesize-research',
        'compliance_check': '/webhook/check-compliance',
        'diagnosis_support': '/webhook/support-diagnosis'
      }
    };

    return appSpecificWorkflows[config.namespace] || baseWorkflows;
  }

  // Get temperature based on content type
  private getTemperatureForType(type: string): number {
    const temperatureMap = {
      description: 0.7,
      summary: 0.3,
      analysis: 0.4,
      creative: 0.8
    };

    return temperatureMap[type as keyof typeof temperatureMap] || 0.5;
  }

  // Health check for application services
  async healthCheck(appConfig?: ApplicationConfig): Promise<any> {
    const factory = this.createAppFactory(appConfig);
    const health: any = {
      application: factory.config.namespace,
      timestamp: new Date().toISOString(),
      services: {}
    };

    // Check primary AI service
    try {
      const primaryService = factory.ai.primary;
      if (primaryService && typeof primaryService.healthCheck === 'function') {
        health.services.primary_ai = await primaryService.healthCheck();
      }
    } catch (error) {
      health.services.primary_ai = false;
    }

    // Check embeddings service
    try {
      const embeddingsService = factory.ai.embeddings;
      if (embeddingsService && typeof embeddingsService.healthCheck === 'function') {
        health.services.embeddings = await embeddingsService.healthCheck();
      }
    } catch (error) {
      health.services.embeddings = false;
    }

    // Check research services
    health.services.research = {};
    for (const service of factory.ai.research) {
      try {
        const serviceName = factory.config.aiProviders.research.find(name => 
          this.getService(name) === service
        );
        if (serviceName && typeof service.healthCheck === 'function') {
          health.services.research[serviceName] = await service.healthCheck();
        }
      } catch (error) {
        // Service health check failed
      }
    }

    // Check workflow service
    if (factory.features.automation) {
      try {
        health.services.workflows = await n8nService.healthCheck();
      } catch (error) {
        health.services.workflows = false;
      }
    }

    return health;
  }
}

// Export singleton instance
export const appFactory = new ApplicationFactory();

// Convenience exports for common operations
export const generateAppContent = (content: string, type: string) => 
  appFactory.generateContent(content, type as any);

export const generateAppEmbeddings = (text: string | string[]) => 
  appFactory.generateEmbeddings(text);

export const gatherAppResearch = (query: string, sources?: string[]) => 
  appFactory.gatherResearchData(query, sources);

export const executeAppWorkflow = (workflowType: string, data: any) => 
  appFactory.executeWorkflow(workflowType, data);

export const checkAppHealth = () => 
  appFactory.healthCheck();

export default appFactory;