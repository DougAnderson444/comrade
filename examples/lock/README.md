
### Symlink

We create a symlink to wit/deps/hypervisor/world.wit by running:

```bash
ln -s /path/to/original/hypervisor/world.wit ./wit/deps/hypervisor/world.wit
```

Next we need to add this dependenciy to our Cargo.toml in the `package.metadata.component.target.dependencies` section:

```toml
# Cargo.toml

[package.metadata.component.target.dependencies]
"comrade:hypervisor" = { path = "wit/deps/hypervisor" }
```
