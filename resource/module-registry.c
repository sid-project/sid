/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2018 Red Hat, Inc. All rights reserved.
 *
 * SID is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * SID is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SID.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "configure.h"

#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include "list.h"
#include "log.h"
#include "mem.h"
#include "module-registry.h"
#include "resource.h"

#define MODULE_REGISTRY_NAME "module-registry"
#define MODULE_NAME "module"

const sid_resource_reg_t sid_resource_reg_module;

struct module_registry {
	const char *directory;
	uint64_t flags;
	unsigned symbol_count;
	const struct sid_module_symbol_params *symbol_params;
	sid_resource_iter_t *module_iter;
};

struct sid_module {
	sid_module_fn_t *init_fn;
	sid_module_fn_t *exit_fn;
	sid_module_fn_t *reload_fn;
	char *name;
	void *handle;
	void **symbols;
	void *data;
};

static sid_resource_t *_find_module(sid_resource_t *module_registry_res, const char *module_name)
{
	struct module_registry *registry = sid_resource_get_data(module_registry_res);
	sid_resource_t *res, *found = NULL;

	sid_resource_iter_reset(registry->module_iter);
	while ((res = sid_resource_iter_next(registry->module_iter))) {
		if (sid_resource_is_registered_by(res, &sid_resource_reg_module)) {
			if (!strcmp(((struct sid_module *) sid_resource_get_data(res))->name, module_name)) {
				found = res;
				break;
			}
		}
	}

	return found;
}

sid_resource_t *sid_module_registry_load_module(sid_resource_t *module_registry_res, const char *module_name)
{
	struct module_registry *registry = sid_resource_get_data(module_registry_res);
	sid_resource_t *module_res;

	if ((module_res = _find_module(module_registry_res, module_name))) {
		log_debug(ID(module_registry_res), "Module %s/%s already loaded, skipping load request.", registry->directory, module_name);
		return module_res;
	}

	if (!(module_res = sid_resource_create(module_registry_res, &sid_resource_reg_module, 0, module_name, module_name))) {
		log_error(ID(module_registry_res), "Failed to load module %s/%s.", registry->directory, module_name);
		return NULL;
	}

	return module_res;
}

sid_resource_t *sid_module_registry_get_module(sid_resource_t *module_registry_res, const char *module_name)
{
	return _find_module(module_registry_res, module_name);
}

int sid_module_registry_unload_module(sid_resource_t *module_res)
{
	return sid_resource_destroy(module_res);
}

int sid_module_registry_get_module_symbols(sid_resource_t *module_res, const void ***ret)
{
	struct sid_module *module = sid_resource_get_data(module_res);

	*ret = (const void **) module->symbols;
	return 0;
}

static const char module_reload_failed_msg[]= "Module-specific reload failed.";

int sid_module_registry_reload_modules(sid_resource_t *module_registry_res)
{
	struct module_registry *registry = sid_resource_get_data(module_registry_res);
	sid_resource_t *res;
	struct sid_module *module;

	sid_resource_iter_reset(registry->module_iter);

	while ((res = sid_resource_iter_next(registry->module_iter))) {
		module = sid_resource_get_data(res);
		if (module->reload_fn && module->reload_fn(module) < 0)
			log_error(ID(res), module_reload_failed_msg);
	}

	return 0;
}

int sid_module_registry_reload_module(sid_resource_t *module_res)
{
	struct sid_module *module = sid_resource_get_data(module_res);

	if (module->reload_fn && module->reload_fn(module) < 0) {
		log_error(ID(module_res), module_reload_failed_msg);
		return -1;
	}

	return 0;
}

void sid_module_set_data(struct sid_module *module, void *data)
{
	module->data = data;
}

void *sid_module_get_data(struct sid_module *module)
{
	return module->data;
}

static int _has_suffix(const char *s, const char *suffix, int no_case)
{
	size_t len_s, len_suffix;

	len_s = strlen(s);
	len_suffix = strlen(suffix);

	if (len_s == 0 || len_suffix > len_s)
		return 0;

	return no_case ? strcasecmp(s + len_s - len_suffix, suffix) == 0
		       : strcmp(s + len_s - len_suffix, suffix) == 0;
}

static int _preload_modules(sid_resource_t *module_registry_res, struct module_registry *registry)
{
	sid_resource_t *module_res;
	struct dirent **dirent = NULL;
	int count, i;
	int r = 0;

	count = scandir(registry->directory, &dirent, NULL, versionsort);

	if (count < 0) {
		log_sys_error(ID(module_registry_res), "scandir", registry->directory);
		r = -1;
		goto out;
	}

	for (i = 0; i < count; i++) {
		if (dirent[i]->d_name[0] != '.' && _has_suffix(dirent[i]->d_name, SID_MODULE_NAME_SUFFIX, 1)) {
			if (!(module_res = sid_resource_create(module_registry_res, &sid_resource_reg_module, 0, dirent[i]->d_name, dirent[i]->d_name)))
				log_error(ID(module_registry_res), "Failed to preload module %s/%s.", registry->directory, dirent[i]->d_name);
		}
		free(dirent[i]);
	}
out:
	free(dirent);
	return r;
}

typedef void (*generic_t) (void);

static int _load_module_symbol(sid_resource_t *module_res, void *dl_handle, const struct sid_module_symbol_params *params, void **symbol_store)
{
	void *symbol;

	if (!(symbol = dlsym(dl_handle, params->name))) {
		if (params->flags & SID_MODULE_SYMBOL_FAIL_ON_MISSING) {
			log_error(ID(module_res), "Failed to load symbol %s: %s.", params->name, dlerror());
			return -1;
		} else if (params->flags & SID_MODULE_SYMBOL_WARN_ON_MISSING)
			log_warning(ID(module_res), "Symbol %s not loaded.", params->name);
	}

	if (params->flags & SID_MODULE_SYMBOL_INDIRECT)
		symbol = symbol ? *((generic_t **) symbol) : NULL;

	*symbol_store = symbol;
	return 0;
}

#define SID_MODULE_INIT_NAME   "sid_module_init"
#define SID_MODULE_EXIT_NAME   "sid_module_exit"
#define SID_MODULE_RELOAD_NAME "sid_module_reload"

static int _init_module(sid_resource_t *module_res, const void *kickstart_data, void **data)
{
	struct module_registry *registry = sid_resource_get_data(sid_resource_get_parent(module_res));
	struct sid_module_symbol_params symbol_params = {0};
	const char *module_name = kickstart_data;
	struct sid_module *module = NULL;
	char path[PATH_MAX];
	unsigned i;

	if (!(module = zalloc(sizeof(*module))) ||
	    !(module->name = strdup(module_name)) ||
	    !(module->symbols = zalloc(registry->symbol_count * sizeof(void *)))) {
		log_error(ID(module_res), "Failed to allocate array to store symbol pointers.");
		goto fail;
	}

	if (snprintf(path, sizeof(path) - 1, "%s/%s", registry->directory, module_name) < 0) {
		log_error(ID(module_res), "Failed to create module directory path.");
		goto fail;
	}

	if (!(module->handle = dlopen(path, RTLD_NOW))) {
		log_error(ID(module_res), "Failed to open module: %s.", dlerror());
		goto fail;
	}

	symbol_params.flags = SID_MODULE_SYMBOL_INDIRECT;
	symbol_params.name = SID_MODULE_RELOAD_NAME;
	if (_load_module_symbol(module_res, module->handle, &symbol_params, (void **) &module->reload_fn) < 0)
		goto fail;

	symbol_params.flags |= SID_MODULE_SYMBOL_FAIL_ON_MISSING;
	symbol_params.name = SID_MODULE_INIT_NAME;
	if (_load_module_symbol(module_res, module->handle, &symbol_params, (void **) &module->init_fn) < 0)
		goto fail;

	symbol_params.name = SID_MODULE_EXIT_NAME;
	if (_load_module_symbol(module_res, module->handle, &symbol_params, (void **) &module->exit_fn) < 0)
		goto fail;

	for (i = 0; i < registry->symbol_count; i++) {
		if (_load_module_symbol(module_res, module->handle, &registry->symbol_params[i], &module->symbols[i]) < 0)
			goto fail;
	}

	if (module->init_fn(module) < 0) {
		log_error(ID(module_res), "Module-specific initialization failed.");
		goto fail;
	}

	*data = module;
	return 0;
fail:
	if (module) {
		if (module->handle)
			(void) dlclose(module->handle);
		free(module->name);
		free(module->symbols);
		free(module);
	}
	return -1;
}

static int _destroy_module(sid_resource_t *module_res)
{
	struct sid_module *module = sid_resource_get_data(module_res);

	if (module->exit_fn(module) < 0)
		log_error(ID(module_res), "Module-specific finalization failed.");

	if (dlclose(module->handle) < 0)
		log_error(ID(module_res), "Failed to close %s module handle: %s.", module->name, dlerror());

	free(module->symbols);
	free(module->name);
	free(module);
	return 0;
}

static int _init_module_registry(sid_resource_t *module_registry_res, const void *kickstart_data, void **data)
{
	const struct sid_module_registry_resource_params *params = kickstart_data;
	struct module_registry *registry = NULL;
	unsigned count = 0;

	if (!params) {
		log_error(ID(module_registry_res), "Module resource parameters not specified.");
		goto fail;
	}

	if (!params->directory || !*params->directory) {
		log_error(ID(module_registry_res), "Module directory not specified.");
		goto fail;
	}

	if (!params->symbol_params) {
		log_error(ID(module_registry_res), "Module's symbol parameters not specified.");
		goto fail;
	}

	if (!(registry = zalloc(sizeof(*registry)))) {
		log_error(ID(module_registry_res), "Failed to allocate module reigistry structure.");
		goto fail;
	}

	/* FIXME: Make a copy of directory name and symbols to load array. */
	registry->directory = params->directory;

	while (params->symbol_params[count].name)
		count++;

	registry->flags = params->flags;
	registry->symbol_count = count;
	registry->symbol_params = params->symbol_params;

	*data = registry;

	if (!(registry->module_iter = sid_resource_iter_create(module_registry_res))) {
		log_error(ID(module_registry_res), "Failed to prepare iterator for modules in module registry.");
		goto fail;
	}

	if ((registry->flags & SID_MODULE_REGISTRY_PRELOAD) && _preload_modules(module_registry_res, registry) < 0) {
		log_error(ID(module_registry_res), "Failed to preload modules from directory %s.", registry->directory);
		goto fail;
	}

	return 0;
fail:
	free(registry);
	return -1;
}

static int _destroy_module_registry(sid_resource_t *module_registry_res)
{
	struct module_registry *registry = sid_resource_get_data(module_registry_res);

	sid_resource_iter_destroy(registry->module_iter);
	free(registry);

	return 0;
}

const sid_resource_reg_t sid_resource_reg_module = {
	.name = MODULE_NAME,
	.init = _init_module,
	.destroy = _destroy_module,
};

const sid_resource_reg_t sid_resource_reg_module_registry = {
	.name = MODULE_REGISTRY_NAME,
	.init = _init_module_registry,
	.destroy = _destroy_module_registry,
};
