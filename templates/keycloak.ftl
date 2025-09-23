#macro css $name
<link rel="stylesheet" href="${url.resourcesPath}/css/${name}.css">
#end

#macro js $name
<script src="${url.resourcesPath}/js/${name}.js" type="text/javascript"></script>
#end

#macro img $name $alt
<img src="${url.resourcesPath}/img/${name}" alt="${alt}">
#end

#macro message $key
${messages[$key]!}
#end

#macro errorIcon
<span class="pf-c-form__helper-text-icon">
    <i class="fas fa-exclamation-circle" aria-hidden="true"></i>
</span>
#end

#macro successIcon
<span class="pf-c-form__helper-text-icon">
    <i class="fas fa-check-circle" aria-hidden="true"></i>
</span>
#end
