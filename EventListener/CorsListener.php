<?php

namespace Easylo\RESTCorsBundle\EventListener;

use Symfony\Component\Routing\Router;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;


class CorsListener
{
    /**
     * Simple headers as defined in the spec should always be accepted
     */
    protected static $simpleHeaders = array(
        'accept',
        'accept-language',
        'content-language',
        'origin',
    );
    protected $dispatcher;
    protected $options;
    protected $router;


    public function __construct(EventDispatcherInterface $dispatcher, Router $router)
    {
        $this->dispatcher = $dispatcher;
        $this->router = $router;
    }

    public function onKernelRequest(GetResponseEvent $event)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $event->getRequestType()) {
            return;
        }
        $request = $event->getRequest();
        // skip if not a CORS request
        if (!$request->headers->has('Origin') || $request->headers->get('Origin') == $request->getSchemeAndHttpHost()) {
            return;
        }
        $options = array();
        $options['allow_credentials'] = true;
        $options['allow_headers'] = true;
        $options['allow_origin'] = true;
        $options['allow_methods'] = $this->getRouteAllowMethods($request);

        // perform preflight checks
        if ('OPTIONS' === $request->getMethod()) {
            //$options = array();

            $event->setResponse($this->getPreflightResponse($request, $options));
            return;
        }
        if (!$this->checkOrigin($request, $options)) {
            return;
        }
        $this->dispatcher->addListener('kernel.response', array($this, 'onKernelResponse'));
        $this->options = $options;
    }

    protected function getRouteAllowMethods(Request $request)
    {
        $options = array();
        $pathinfo = $request->getPathInfo();

        $collection = $this->router->getRouteCollection();
        $allRoutes = $collection->all();
        foreach ($allRoutes as $routeName => $route) {
            $compiledRoute = $route->compile();

            // check the static prefix of the URL first. Only use the more expensive preg_match when it matches
            if ('' !== $compiledRoute->getStaticPrefix() && 0 !== strpos($pathinfo, $compiledRoute->getStaticPrefix())) {
                continue;
            }

            if (!preg_match($compiledRoute->getRegex(), $pathinfo, $matches)) {
                continue;
            }

            $hostMatches = array();
            if ($compiledRoute->getHostRegex() && !preg_match($compiledRoute->getHostRegex(), $this->context->getHost(), $hostMatches)) {
                continue;
            }

            foreach ($route->getMethods() as $routeMethods) {
                $options[] = $routeMethods;
            }

        }

        return $options;

    }

    protected function getPreflightResponse(Request $request, array $options = array())
    {
        $response = new Response();
        if ($options['allow_credentials']) {
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
        }
        if ($options['allow_methods']) {
            $response->headers->set('Access-Control-Allow-Methods', implode(', ', $options['allow_methods']));
        }
        if ($options['allow_headers']) {
            $headers = $options['allow_headers'] === true
                ? $request->headers->get('Access-Control-Request-Headers')
                : implode(', ', $options['allow_headers']);
            $response->headers->set('Access-Control-Allow-Headers', $headers);
        }
        /*if ($options['max_age']) {
            $response->headers->set('Access-Control-Max-Age', $options['max_age']);
        }
        if (!$this->checkOrigin($request, $options)) {
            $response->headers->set('Access-Control-Allow-Origin', 'null');
            return $response;
        }*/
        $response->headers->set('Access-Control-Allow-Origin', $request->headers->get('Origin'));
        // check request method
        if (!in_array(strtoupper($request->headers->get('Access-Control-Request-Method')), $options['allow_methods'], true)) {
            //$response->setStatusCode(405);
            //return $response;
        }
        /**
         * We have to allow the header in the case-set as we received it by the client.
         * Firefox f.e. sends the LINK method as "Link", and we have to allow it like this or the browser will deny the
         * request.
         */
        if (!in_array($request->headers->get('Access-Control-Request-Method'), $options['allow_methods'], true)) {
            $options['allow_methods'][] = $request->headers->get('Access-Control-Request-Method');
            $response->headers->set('Access-Control-Allow-Methods', implode(', ', $options['allow_methods']));
        }
        // check request headers
        $headers = $request->headers->get('Access-Control-Request-Headers');
        if ($options['allow_headers'] !== true && $headers) {
            $headers = trim(strtolower($headers));
            foreach (preg_split('{, *}', $headers) as $header) {
                if (in_array($header, self::$simpleHeaders, true)) {
                    continue;
                }
                if (!in_array($header, $options['allow_headers'], true)) {
                    $response->setStatusCode(400);
                    $response->setContent('Unauthorized header ' . $header);
                    break;
                }
            }
        }
        return $response;
    }

    protected function checkOrigin(Request $request, array $options)
    {
        // check origin
        $origin = $request->headers->get('Origin');
        if ($options['allow_origin'] === true) return true;
        if ($options['origin_regex'] === true) {
            // origin regex matching
            foreach ($options['allow_origin'] as $originRegexp) {
                if (preg_match('{' . $originRegexp . '}i', $origin)) {
                    return true;
                }
            }
        } else {
            // old origin matching
            if (in_array($origin, $options['allow_origin'])) {
                return true;
            }
        }
        return false;
    }

    public function onKernelResponse(FilterResponseEvent $event)
    {
        if (HttpKernelInterface::MASTER_REQUEST !== $event->getRequestType()) {
            return;
        }
        $response = $event->getResponse();
        $request = $event->getRequest();
        // add CORS response headers
        $response->headers->set('Access-Control-Allow-Origin', $request->headers->get('Origin'));
        if ($this->options['allow_credentials']) {
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
        }
    }

}
